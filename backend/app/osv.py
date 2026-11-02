"""OSV (osv.dev): the fixed versions and version ranges of open-source packages – for the CVEs of findings of followed
products that name their packages in the catalogue (`osv: [[Maven, org.apache.tomcat:tomcat-catalina], …]`).

- Only by id: GET https://api.osv.dev/v1/vulns/<CVE> and, for the ids it names as aliases (GHSA-…, GO-…, PYSEC-…,
  RUSTSEC-…),
  GET …/vulns/<alias> – never a product name or a version (no /v1/query). Only vulnerability ids leave the machine.
- ECOSYSTEM and SEMVER ranges are kept (introduced / fixed / last_affected) with the listed versions; GIT ranges
  (commit hashes) say nothing about an installed release and are dropped. Packages of other ecosystems than the
  catalogue's (Debian, Alpine …) are dropped too. A withdrawn record (`withdrawn`) is not used at all.
- Stored as a Vendor News advisory `osv:<CVE>` (source osv) – grouped under the CVE's other records, judged after the
  vendor, the NVD and cvelistV5 (vendor.cve_verdict): it decides a "possibly affected" and names a missing fix.
- Each CVE at most once a day while it is young (published in the last 30 days), else once a week; PER_ROUND CVEs a
  round, ALIASES requests more each.
"""

import asyncio
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import catalog_data, source_health
from app import vendor_sources as src
from app.models import VendorFetch
from app.news import NewsError, _date

log = logging.getLogger("cobe_news.osv")

API = "https://api.osv.dev/v1/vulns/"
KEY = "osv:api"  # vendor_fetch: the source's state (backoff, health)
PER_CVE = "osvcve:"  # vendor_fetch: when one CVE was asked (no source of its own)
PER_ROUND = 25
ALIASES = 3
YOUNG = timedelta(days=30)
EVERY_YOUNG = timedelta(days=1)
EVERY_OLD = timedelta(days=7)
LIMIT = 4 * 1024 * 1024
MAX_PACKAGES = 60
MAX_RANGES = 40
MAX_VERSIONS = 300
ID = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,15}-[A-Za-z0-9._:-]{3,80}$")
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ECOSYSTEMS = {e.lower(): e for e in catalog_data.OSV_ECOSYSTEMS}


# aliases worth a request first: reviewed advisories of package ecosystems (GitHub, Go, PyPA, RustSec), then the rest
PREFERRED = ("GHSA-", "GO-", "PYSEC-", "RUSTSEC-")


def _rank(alias: str) -> tuple[int, str]:
    return (next((i for i, p in enumerate(PREFERRED) if alias.startswith(p)), len(PREFERRED)), alias)


def vuln_url(ident: str) -> str:
    return API + quote(ident, safe="-._:")


@src._shaped
def parse(data: bytes) -> dict:
    """One OSV record: id, aliases, summary, modified, and the packages of the catalogue's ecosystems with their
    ECOSYSTEM/SEMVER ranges ({introduced, fixed, last_affected} each) and listed versions."""
    doc = src._json(data)
    if not isinstance(doc, dict) or not ID.match(src._s(doc.get("id"), 100)):
        raise NewsError("format", "no OSV record")
    packages = []
    for a in src._l(doc.get("affected")):
        if not isinstance(a, dict):
            continue
        pkg = src._d(a.get("package"))
        eco = src._s(pkg.get("ecosystem"), 60)
        name = src._s(pkg.get("name"), 200)
        if not name or eco.split(":")[0].lower() not in ECOSYSTEMS:
            continue
        ranges = []
        for r in src._l(a.get("ranges")):
            if not isinstance(r, dict) or r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT: commits, no releases
            cur: dict = {}
            for ev in src._l(r.get("events")):
                if not isinstance(ev, dict):
                    continue
                if "introduced" in ev:
                    if cur:
                        ranges.append(cur)
                    cur = {"introduced": src._s(ev.get("introduced"), 64) or "0"}
                elif "fixed" in ev or "last_affected" in ev:
                    k = "fixed" if "fixed" in ev else "last_affected"
                    cur = {"introduced": "0", **cur, k: src._s(ev.get(k), 64)}
                    ranges.append(cur)
                    cur = {}
            if cur:
                ranges.append(cur)
        versions = [src._s(v, 64) for v in src._l(a.get("versions")) if isinstance(v, str)][:MAX_VERSIONS]
        if ranges or versions:
            packages.append({"ecosystem": ECOSYSTEMS[eco.split(":")[0].lower()], "name": name, "ranges": ranges[:MAX_RANGES], "versions": versions})
    return {
        "id": src._s(doc.get("id"), 100),
        # OSV's retraction: a withdrawn record says nothing any more (to_advisory leaves it out)
        "withdrawn": bool(src._s(doc.get("withdrawn"), 40)),
        "aliases": [a for a in (src._s(x, 100) for x in src._l(doc.get("aliases"))) if ID.match(a)][:20],
        "summary": src._s(doc.get("summary"), 400) or src._s(doc.get("details"), 400),
        "modified": src._s(doc.get("modified"), 40),
        "published": src._s(doc.get("published"), 40),
        "packages": packages[:MAX_PACKAGES],
    }


def to_advisory(cve: str, records: list[dict]) -> dict | None:
    """The OSV records of one CVE (its own and its aliases') as one advisory – None without a usable package range."""
    records = [r for r in records if not r.get("withdrawn")]
    packages: dict[tuple, dict] = {}
    for r in records:
        for p in r["packages"]:
            k = (p["ecosystem"], p["name"])
            e = packages.setdefault(k, {"ecosystem": p["ecosystem"], "name": p["name"], "ranges": [], "versions": []})
            for x in p["ranges"]:
                if x not in e["ranges"] and len(e["ranges"]) < MAX_RANGES:
                    e["ranges"].append(x)
            e["versions"] = list(dict.fromkeys([*e["versions"], *p["versions"]]))[:MAX_VERSIONS]
    if not packages:
        return None
    ids = [r["id"] for r in records if r["id"] != cve]
    summary = next((r["summary"] for r in records if r["summary"]), "")
    modified = max((d for r in records if (d := _date(r["modified"]))), default=None)
    published = min((d for r in records if (d := _date(r["published"]))), default=None)
    return {
        "id": f"osv:{cve}",
        "source": "osv",
        "ident": cve,
        "title": summary[:300] or cve,
        "summary": summary,
        "url": f"https://osv.dev/vulnerability/{(ids or [cve])[0]}",
        "cves": [cve],
        "cvss": None,
        "severity": "info",
        "published_at": published,
        "updated_at": modified,
        "data": {"packages": list(packages.values())[:MAX_PACKAGES], "ids": ids[:10]},
    }


async def wanted(db: AsyncSession) -> list[tuple[str, str | None]]:
    """(CVE, published) of the findings of followed products with OSV packages that concern a version (not "not
    affected") – from the cached views."""
    from app import vendor

    out: dict[str, str | None] = {}
    fs = await vendor.follows(db)
    vers = await vendor.versions_of(db, [f.id for f in fs])
    kev, euvd = await vendor.kev_index(db), await vendor.euvd_cves(db)
    for f in fs:
        p = vendor.product_of(f)
        if not p or not p.get("osv"):
            continue
        view = await vendor.product_view(db, f, vers.get(f.id, []), kev=kev, euvd=euvd)
        for x in view["findings"]:
            if x["status"] in ("affected", "possible", "unversioned"):
                for c in x["cves"]:
                    if CVE_ID.match(c):
                        out.setdefault(c, x.get("published_at"))
    return list(out.items())


async def refresh(db: AsyncSession, *, force: bool = False) -> int | None:
    """The OSV records of the wanted CVEs that are due (PER_ROUND a round); returns how many advisories changed."""
    from app import vendor

    st = await vendor._state(db, KEY)
    now = datetime.now(UTC)
    if not vendor._due(st, now, force):
        return None
    want = await wanted(db)
    if not want:
        await db.commit()
        return None
    asked = {k.removeprefix(PER_CVE): at for k, at in (await db.execute(select(VendorFetch.key, VendorFetch.last_fetch_at).where(VendorFetch.key.in_([PER_CVE + c for c, _ in want])))).all()}

    def due(c: str, pub: str | None) -> bool:
        at = asked.get(c)
        young = (d := _date(pub or "")) is not None and now - d < YOUNG
        return at is None or now - at >= (EVERY_YOUNG if young else EVERY_OLD)

    todo = [c for c, pub in want if due(c, pub)]
    if not todo:
        st.next_fetch_at = now + timedelta(hours=1)
        await db.commit()
        return None
    ix = await vendor.current_index(db)
    meter = source_health.start()
    changed = done = bad = 0
    try:
        for cve in todo[:PER_ROUND]:
            records = []
            try:
                body = await vendor.get(vuln_url(cve), db=db, conditional=False, limit=LIMIT)
                own = await asyncio.to_thread(parse, body or b"{}")
                records.append(own)
                for alias in sorted((a for a in own["aliases"] if not a.startswith("CVE-")), key=_rank)[:ALIASES]:  # (also of a withdrawn record)
                    try:
                        records.append(await asyncio.to_thread(parse, await vendor.get(vuln_url(alias), db=db, conditional=False, limit=LIMIT) or b"{}"))
                    except NewsError as exc:
                        if exc.category in ("rate_limited", "timeout", "connection"):
                            raise
                        bad += exc.category == "format"
            except NewsError as exc:
                if exc.category == "http" and "404" in (exc.detail or ""):
                    records = []  # OSV does not know the CVE (yet): asked, nothing to store
                elif exc.category == "format":
                    bad += 1
                    records = []
                else:
                    raise
            row = await db.get(VendorFetch, PER_CVE + cve)
            if row is None:
                row = VendorFetch(key=PER_CVE + cve, failures=0, items=0)
                db.add(row)
            row.last_fetch_at = row.last_ok_at = datetime.now(UTC)
            await db.commit()
            adv = to_advisory(cve, records) if records else None
            if adv is not None:
                changed += await vendor.store(db, [adv], ix)
            elif records:
                # withdrawn since it was stored – or no package range any more: the old copy must not decide any longer
                changed += await vendor.drop_advisories(db, [f"osv:{cve}"], withdrawn=all(r.get("withdrawn") for r in records))
            done += 1
        st = await vendor._state(db, KEY)
        vendor._ok(st, timedelta(minutes=10) if len(todo) > done else timedelta(hours=1), done)
        vendor._record(db, st, meter, items=changed, parse_errors=bad)
    except Exception as exc:  # noqa: BLE001 - OSV pauses, nothing else does
        await db.rollback()
        st = await vendor._state(db, KEY)
        vendor._record(db, st, meter, exc=vendor._fail(st, exc, timedelta(hours=1)))
    await db.commit()
    return changed
