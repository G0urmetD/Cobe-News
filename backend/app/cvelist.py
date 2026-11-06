"""cvelistV5 (github.com/CVEProject/cvelistV5): the CVE records as the CNAs publish them – changes only, never the
whole list (the all_CVEs zip, ~650 MB, is never downloaded).

- Hourly: the newest release (api.github.com …/releases/latest, conditional) names a zip of every record changed
  since midnight UTC (`<day>_delta_CVEs_at_<hhmm>Z.zip`, a few hundred KB to a few MB). A day the round missed is
  read from that day's `<day>_delta_CVEs_at_end_of_day.zip` (its release by tag), DAYS_BACK days at most.
- Kept: the records that concern a followed product (the CNA names it, or CISA's ADP lists one of its CPEs) and the
  records stored before (an update) – not every CVE. A rejected record removes the stored one.
- On demand, one at a time (raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<year>/<n>xxx/<CVE>.json): the
  CVEs of findings whose NVD record has no CPE configuration yet ("Awaiting Analysis") and of stories the NVD cannot
  describe – each at most once a week, SINGLE_PER_ROUND a round.
- Stored as Vendor News advisories `cvelist:<CVE>` (source cvelist) in the shape of the NVD's (`cna`: the CNA's
  affected rows, `adp`: CISA's) plus SSVC, KEV and CVSS from CISA's ADP container. Judged after the vendor and – where
  it has CPE configurations – the NVD (vendor.cve_verdict); the NVD stays for the CPE matching.
Only public GitHub addresses are asked; nothing about the installation leaves the machine.
"""

import asyncio
import io
import json
import logging
import re
import struct
import zipfile
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app import db as dbm
from app import source_health
from app import vendor_sources as src
from app.models import VendorAdvisory, VendorAdvisoryProduct, VendorFetch
from app.news import NewsError, _date

log = logging.getLogger("cobe_news.cvelist")

REPO = "CVEProject/cvelistV5"
LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
BY_TAG = f"https://api.github.com/repos/{REPO}/releases/tags/" + "{tag}"
DOWNLOAD = f"https://github.com/{REPO}/releases/download/"
RAW = f"https://raw.githubusercontent.com/{REPO}/main/cves/" + "{year}/{bucket}/{cve}.json"
GH_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
DELTA_KEY = "cvelist:delta"
SINGLE_KEY = "cvelist:single"  # the on-demand lookups of a round, as one fetch
PER_CVE = "cvelistcve:"  # vendor_fetch: when one CVE was asked (no source of its own)
ASSET = re.compile(r"^(\d{4}-\d{2}-\d{2})_delta_CVEs_at_(\d{4}Z|end_of_day)\.zip$")
DELTA_EVERY = timedelta(hours=1)  # how often the round looks whether a slot or the day change is due (no request else)
SLOTS = (5, 11, 17)  # UTC hours: the day's cumulative zip is read once the release of this hour is out
EOD_GRACE = "0600Z"  # until the day's release of this hour, a missing end-of-day zip of the day before is waited for
DAYS_BACK = 3
RELEASE_LIMIT = 4 * 1024 * 1024
DELTA_LIMIT = 64 * 1024 * 1024  # an end-of-day zip is ~5–7 MB; a mass update by a CNA can be bigger
ENTRY_LIMIT = 2 * 1024 * 1024  # one record unzipped (the biggest real ones – Linux kernel – are a few hundred KB)
UNZIPPED_LIMIT = 256 * 1024 * 1024  # the whole zip unzipped as declared (no zip bomb; read one entry at a time)
MAX_ENTRIES = 100_000  # checked in the end-of-central-directory record before the zip is opened
CD_LIMIT = 16 * 1024 * 1024  # the central directory (~100 bytes an entry)
MAX_VERSION_ROWS = 2000  # rows of one record kept (versions of all affected entries; changes count too)
RECORD_LIMIT = 8 * 1024 * 1024
SINGLE_EVERY = timedelta(days=7)
SINGLE_PER_ROUND = 20
CVE_ID = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")


# ---------------------------------------------------------------- parsing (pure)


def raw_url(cve: str) -> str:
    m = CVE_ID.match(cve)
    if not m:
        raise ValueError(cve)
    return RAW.format(year=m.group(1), bucket=f"{int(m.group(2)) // 1000}xxx", cve=cve)


@src._shaped
def parse_release(data: bytes) -> dict:
    """A release of cvelistV5 (GitHub API): its tag and the delta zip – {tag, day, at, url, size}. Only an asset named
    like a delta and served from the repository's own download path is taken (never the all_CVEs zip)."""
    doc = src._json(data)
    if not isinstance(doc, dict):
        raise NewsError("format", "no release")
    for a in src._l(doc.get("assets")):
        if not isinstance(a, dict):
            continue
        name, link = src._s(a.get("name"), 200), src._s(a.get("browser_download_url"), 500)
        m = ASSET.match(name)
        if m and link.startswith(DOWNLOAD) and link.endswith("/" + name) and "all_CVEs" not in name:
            size = a.get("size") if isinstance(a.get("size"), int) else 0
            return {"tag": src._s(doc.get("tag_name"), 100), "day": m.group(1), "at": m.group(2), "url": link, "size": size}
    raise NewsError("format", "release without a delta zip")


def _metric(metrics) -> tuple[float | None, str, str]:  # noqa: ANN001
    """(score, severity, vector) of the first CVSS of a container's metrics: 4.0, 3.1, 3.0."""
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        for m in src._l(metrics):
            d = src._d(m.get(key)) if isinstance(m, dict) else {}
            if (s := src._score(d.get("baseScore"))) is not None:
                return s, src._s(d.get("baseSeverity"), 20), src._s(d.get("vectorString"), 200)
    return None, "", ""


def _rows(affected, *, cpes: bool) -> list[dict]:  # noqa: ANN001
    """CVE 5 affected rows as Vendor News keeps them (as the NVD's copy, vendor_sources._trim_cna); ADP rows with
    their CPEs (the product as CPE names it)."""
    out = []
    budget = MAX_VERSION_ROWS  # a bloated record (60 x 200 versions x 60 changes) keeps no more than this
    for a in src._l(affected)[:60]:
        if not isinstance(a, dict):
            continue
        versions = []
        for x in src._l(a.get("versions"))[:200]:
            if budget <= 0:
                break
            if isinstance(x, dict):
                row = {k: src._s(x[k], 64) for k in ("version", "lessThan", "lessThanOrEqual", "status", "versionType") if isinstance(x.get(k), str)}
                ch = [{"at": src._s(c.get("at"), 64), "status": src._s(c.get("status"), 20)} for c in src._l(x.get("changes"))[:60] if isinstance(c, dict)][: max(0, min(60, budget - 1))]
                if ch:
                    row["changes"] = ch
                versions.append(row)
                budget -= 1 + len(ch)
        row = {"vendor": src._s(a.get("vendor"), 120), "product": src._s(a.get("product"), 200), "defaultStatus": src._s(a.get("defaultStatus"), 20), "versions": versions}
        if cpes:
            row["cpes"] = [c for c in (src._s(x, 300) for x in src._l(a.get("cpes"))) if c.startswith("cpe:2.3:")][:20]
        out.append(row)
    return [{"affectedData": out}] if out else []


def _ssvc_kev(adp: list) -> tuple[dict | None, dict | None, tuple[float | None, str, str]]:
    """CISA's ADP ("CISA ADP Vulnrichment"): SSVC decision points, the KEV listing, CVSS."""
    ssvc = kev = None
    score: tuple[float | None, str, str] = (None, "", "")
    for c in adp:
        for m in src._l(c.get("metrics")):
            other = src._d(src._d(m).get("other"))
            content = src._d(other.get("content"))
            if other.get("type") == "ssvc" and ssvc is None:
                opts = {}
                for o in src._l(content.get("options")):
                    for k, v in src._d(o).items():
                        opts[str(k).lower()] = src._s(v, 20).lower()
                ssvc = {"exploitation": opts.get("exploitation", ""), "automatable": opts.get("automatable", ""), "technical_impact": opts.get("technical impact", ""), "at": src._s(content.get("timestamp"), 40)}
            elif other.get("type") == "kev" and kev is None:
                kev = {"added": src._s(content.get("dateAdded"), 10), "due": ""}
        if score[0] is None:
            score = _metric(c.get("metrics"))
    return ssvc, kev, score


def parse_record(doc) -> dict | str | None:  # noqa: ANN001
    """One CVE 5 record (decoded JSON) as an advisory; "rejected:<CVE>" for a rejected record; None for anything else."""
    if not isinstance(doc, dict):
        return None
    doc = src.clean(doc)
    meta = src._d(doc.get("cveMetadata"))
    cid = src._s(meta.get("cveId"), 32).upper()
    if not CVE_ID.match(cid):
        return None
    if src._s(meta.get("state"), 20).upper() == "REJECTED":
        return f"rejected:{cid}"
    cont = src._d(doc.get("containers"))
    cna = src._d(cont.get("cna"))
    adp = [c for c in src._l(cont.get("adp")) if isinstance(c, dict) and src._s(src._d(c.get("providerMetadata")).get("shortName"), 40).upper().startswith("CISA")]
    desc = next((src._s(d.get("value"), 4000) for d in src._l(cna.get("descriptions")) if isinstance(d, dict) and str(d.get("lang") or "").startswith("en")), "")
    score, given, vector = _metric(cna.get("metrics"))
    ssvc, kev, adp_score = _ssvc_kev(adp)
    from_adp = False
    if score is None and adp_score[0] is not None:
        score, given, vector = adp_score
        from_adp = True
    cwe = []
    for pt in src._l(cna.get("problemTypes")):
        for d in src._l(src._d(pt).get("descriptions")):
            w = src._s(src._d(d).get("cweId"), 20)
            if re.fullmatch(r"CWE-\d{1,5}", w) and w not in cwe:
                cwe.append(w)
    short = re.sub(r"\s+", " ", desc)
    title = src._s(cna.get("title"), 300) or (short[:180] + (" …" if len(short) > 180 else ""))
    exploited = bool(kev) or (ssvc or {}).get("exploitation") == "active"
    return {
        "id": f"cvelist:{cid}",
        "source": "cvelist",
        "ident": cid,
        "title": title,
        "summary": desc[:1500],
        "url": f"https://www.cve.org/CVERecord?id={cid}",
        "cves": [cid],
        "cvss": score,
        "severity": src.severity_of(score, given),
        "exploited": exploited,
        "published_at": _date(src._s(meta.get("datePublished"), 40)),
        "updated_at": _date(src._s(meta.get("dateUpdated"), 40)),
        "data": {
            "configs": [],
            "cna": _rows(cna.get("affected"), cpes=False),
            "adp": _rows([a for c in adp for a in src._l(c.get("affected"))], cpes=True),
            "desc": desc[:1500],
            "cwe": cwe[:5],
            # the CNA: is its affected data the vendor's own word? (vendor_match.cna_by)
            "assigner": src._s(meta.get("assignerShortName"), 60) or src._s(src._d(cna.get("providerMetadata")).get("shortName"), 60),
            "cvss_vector": vector,
            "cvss_from_adp": from_adp,
            "ssvc": ssvc,
            "kev": kev,
        },
    }


def parse_one(data: bytes) -> dict | str | None:
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise NewsError("format", f"no JSON: {str(exc)[:80]}") from exc
    try:
        return parse_record(doc)
    except (*src.SHAPE, RecursionError) as exc:  # RecursionError: nesting json.loads takes, clean() does not (L3)
        raise NewsError("format", f"unexpected structure ({type(exc).__name__})") from exc


def _eocd_entries(blob: bytes) -> tuple[int, int]:
    """(entries, central directory size) from the end-of-central-directory record (zip64 too) – read before ZipFile()
    parses the whole central directory (600k entries: 13 s and 320 MB – security review L4)."""
    i = blob.rfind(b"PK\x05\x06", max(0, len(blob) - 65557))
    if i < 0 or len(blob) < i + 22:
        raise NewsError("format", "no zip")
    _, _, _, _, total, cd_size, _, _ = struct.unpack_from("<4s4H2LH", blob, i)
    if total == 0xFFFF or cd_size == 0xFFFFFFFF:
        j = blob.rfind(b"PK\x06\x06", max(0, i - 4096), i)  # zip64 end of central directory record
        if j < 0 or len(blob) < j + 56:
            raise NewsError("format", "zip64 without its record")
        total, cd_size = struct.unpack_from("<QQ", blob, j + 32)
    return total, cd_size


def open_delta(blob: bytes) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    """A delta zip and its JSON entries – the entry count and the sizes checked before anything is unpacked."""
    total, cd_size = _eocd_entries(blob)
    if total > MAX_ENTRIES or cd_size > CD_LIMIT:
        raise NewsError("too_large", f"delta zip with {total} entries")
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except (zipfile.BadZipFile, *src.SHAPE, OSError, EOFError, NotImplementedError) as exc:
        raise NewsError("format", "no zip") from exc
    infos = [i for i in z.infolist() if not i.is_dir() and i.filename.endswith(".json")]
    if len(infos) > MAX_ENTRIES or sum(i.file_size for i in infos) > UNZIPPED_LIMIT:
        raise NewsError("too_large", "delta zip unpacks too large")
    return z, infos


def entry_cve(info: zipfile.ZipInfo) -> str | None:
    """The CVE an entry is named after (deltaCves/CVE-2026-1234.json) – None for anything else."""
    name = info.filename.rsplit("/", 1)[-1].removesuffix(".json").upper()
    return name if CVE_ID.match(name) else None


def read_entries(z: zipfile.ZipFile, infos: list[zipfile.ZipInfo], followed=None, known: set[str] | None = None) -> tuple[list[dict], list[str], int]:  # noqa: ANN001
    """The entries one at a time: (advisories, rejected CVE ids, unreadable entries). With `followed` (a vendor.Index)
    only what is kept at once – a record that concerns a followed product (vendor.link) or is stored already (`known`,
    ids `cvelist:<CVE>`) – everything else is dropped as soon as it is parsed: a big delta never sits in memory (H3).
    One unreadable entry (bad deflate data, a wrong size, an unknown compression) is one bad entry, never the zip (L1)."""
    from app import vendor

    known = known or set()
    advs, rejected, bad = [], [], 0
    for i in infos:
        cid = entry_cve(i)
        if i.file_size > ENTRY_LIMIT or cid is None:
            bad += 1
            continue
        try:
            with z.open(i) as f:
                data = f.read(ENTRY_LIMIT + 1)
            if len(data) > ENTRY_LIMIT:
                raise ValueError("entry larger than declared")
            got = parse_record(json.loads(data))
        except MemoryError:
            raise
        except Exception:  # noqa: BLE001 - zlib.error, LZMAError, BadZipFile, OSError, NotImplementedError, ValueError …
            bad += 1
            continue
        finally:
            data = None
        if isinstance(got, str):
            c = got.removeprefix("rejected:")
            if followed is None or f"cvelist:{c}" in known:
                rejected.append(c)
        elif got is not None and (followed is None or got["id"] in known or vendor.link(got, followed)):
            advs.append(got)
    return advs, rejected, bad


def read_delta(blob: bytes, followed=None, known: set[str] | None = None) -> tuple[list[dict], list[str], int]:  # noqa: ANN001
    """A delta zip: (advisories, rejected CVE ids, unreadable entries) – see read_entries."""
    z, infos = open_delta(blob)
    with z:
        return read_entries(z, infos, followed, known)


# ---------------------------------------------------------------- the hourly delta


def _cursor(st: VendorFetch) -> dict:
    try:
        c = json.loads(st.cursor or "{}")
    except ValueError:
        c = {}
    return c if isinstance(c, dict) else {}


async def _release(db: AsyncSession, url: str, st: VendorFetch | None = None) -> dict | None:
    from app import vendor

    body = await vendor.get(url, db=db, st=st, headers=GH_HEADERS, limit=RELEASE_LIMIT, conditional=st is not None)
    return None if body is None else await asyncio.to_thread(parse_release, body)


async def _apply(db: AsyncSession, rel: dict, followed, ix) -> tuple[int, int]:  # noqa: ANN001
    """One delta zip: the records that concern a followed product or were stored before go in; rejected ones out. The
    stored ones are looked up by the entries' names first – the records themselves are filtered while they are read."""
    from app import vendor

    if rel["size"] > DELTA_LIMIT:
        raise NewsError("too_large", f"{rel['size'] // 1024} KB")
    blob = await vendor.get(rel["url"], db=db, conditional=False, limit=DELTA_LIMIT, headers={"Accept": "application/octet-stream"})
    z, infos = await asyncio.to_thread(open_delta, blob or b"")
    with z:
        ids = [f"cvelist:{c}" for i in infos if (c := entry_cve(i))]
        known: set[str] = set()
        for i in range(0, len(ids), 2000):
            known.update(await db.scalars(select(VendorAdvisory.id).where(VendorAdvisory.id.in_(ids[i : i + 2000]))))
        await dbm.release(db)
        del blob, ids
        keep, rejected, bad = await asyncio.to_thread(read_entries, z, infos, followed, known)
    changed = await vendor.store(db, keep, ix)
    await vendor.drop_advisories(db, [f"cvelist:{c}" for c in rejected])
    return changed, bad


def _passing(exc: NewsError) -> bool:
    return exc.category in ("rate_limited", "timeout", "connection") or (exc.category == "http" and bool(re.search(r"HTTP 5\d\d", exc.detail or "")))


def _slot(at: str) -> int:
    """The last slot (SLOTS) a release of the day at `at` ("0700Z", "end_of_day") covers; -1: none yet."""
    if at == "end_of_day":
        return 24
    try:
        hour = int(at[:2])
    except ValueError:
        return -1
    return max((x for x in SLOTS if hour >= x), default=-1)


def _clock_due(cur: dict, now: datetime) -> bool:
    """Whether a look at the newest release is worth it now (no request otherwise): nothing read yet, an end-of-day zip
    pending, the day changed, or a slot passed (by the clock, ~20–40 minutes after the hour) the cursor has not read."""
    if not cur.get("day") or cur.get("eod"):
        return True
    today = now.date().isoformat()
    if cur["day"] < today:
        return True
    hour = now.hour if now.minute >= 20 else now.hour - 1
    return _slot(f"{max(hour, 0):02d}00Z") > _slot(str(cur.get("at") or ""))


def _eod_waiting(day: str, seen: dict) -> bool:
    """An end-of-day zip of `day` not out yet is waited for while the newest release is of the next day before EOD_GRACE
    (GitHub publishes it after the first release of the next day – 00:31 vs 00:37 on 2026-10-28) or still of `day`."""
    nxt = (date.fromisoformat(day) + timedelta(days=1)).isoformat()
    sday, sat = str(seen.get("day") or ""), str(seen.get("at") or "")
    return sday <= day or (sday == nxt and sat != "end_of_day" and sat < EOD_GRACE)


async def sync_delta(db: AsyncSession, products: list[dict], ix, force: bool) -> int | None:  # noqa: ANN001
    """The day's cumulative zip three times a day (SLOTS), the end-of-day zip of each day after it ended – about 9–11 MB a
    day instead of ~50 MB for every hourly release, a change is read within ~7.5 hours. The cursor: the day and the
    release last read of it ("day", "at", "tag"), the days whose end-of-day zip is still to read ("eod") and the newest
    release seen ("seen"). A zip that cannot be read (too large, broken) is one error, the others go on (M4); a passing
    failure keeps what is pending for the next round."""
    from app import vendor

    st = await vendor._state(db, DELTA_KEY)
    now = datetime.now(UTC)
    if not vendor._due(st, now, force):
        return None
    cur = _cursor(st)
    if not force and not _clock_due(cur, now):
        vendor._ok(st, DELTA_EVERY, 0)
        await db.commit()
        return None
    followed = vendor.index_of(products)
    changed = bad = 0
    errors: list[str] = []
    meter = source_health.start()
    pending = [d for d in cur.get("eod") or [] if isinstance(d, str)]

    def cursor() -> str:
        keep = {k: cur[k] for k in ("tag", "day", "at") if cur.get(k) is not None}
        return json.dumps({**keep, **({"eod": sorted(pending)} if pending else {}), **({"seen": cur["seen"]} if cur.get("seen") else {})})

    try:
        latest = await _release(db, LATEST, st)
        first_run = not cur.get("day")
        if latest is not None:
            cur["seen"] = {k: latest[k] for k in ("tag", "day", "at")}
            eod = latest["at"] == "end_of_day"
            today = (date.fromisoformat(latest["day"]) + timedelta(days=1)).isoformat() if eod else latest["day"]
            if first_run:
                if eod:
                    pending.append(latest["day"])
                cur.update(day=today, at="", tag="")
            elif cur["day"] < today:
                # the day changed: each day since the last one read by its end-of-day zip (the last DAYS_BACK at most)
                d = date.fromisoformat(cur["day"]) + timedelta(days=1 if cur.get("at") == "end_of_day" else 0)
                d = max(d, date.fromisoformat(today) - timedelta(days=DAYS_BACK))
                while d.isoformat() < today:
                    if d.isoformat() not in pending:
                        pending.append(d.isoformat())
                    d += timedelta(days=1)
                cur.update(day=today, at="", tag="")
        seen = cur.get("seen") or {}
        oldest = (date.fromisoformat(str(cur.get("day") or now.date().isoformat())) - timedelta(days=DAYS_BACK)).isoformat()
        pending = sorted(p for p in pending if p >= oldest)
        for day in list(pending):
            tag = f"cve_{day}_at_end_of_day"
            try:
                rel = latest if latest is not None and latest["tag"] == tag else await _release(db, BY_TAG.format(tag=tag))
                if rel is not None:
                    n, b = await _apply(db, rel, followed, ix)
                    changed, bad = changed + n, bad + b
            except NewsError as exc:
                if exc.category == "http" and "404" in (exc.detail or "") and _eod_waiting(day, seen):
                    log.info("cvelist: %s not out yet – waiting", tag)
                    continue  # stays pending: the last hours of the day are not lost (M3)
                if _passing(exc):
                    raise  # the next round again (pending is kept)
                errors.append(f"{tag}: {exc.category}")  # gone, too large or broken: this day is skipped, the rest goes on (M4)
                log.info("cvelist: %s skipped: %s", tag, f"{exc.category}: {exc.detail}")
            pending.remove(day)
        if latest is not None and latest["at"] != "end_of_day" and latest["day"] == cur.get("day") and latest["tag"] != cur.get("tag"):
            # today's cumulative zip: at once the first time, then once each slot (SLOTS) is out
            if first_run or _slot(latest["at"]) > _slot(str(cur.get("at") or "")):
                try:
                    n, b = await _apply(db, latest, followed, ix)
                    changed, bad = changed + n, bad + b
                except NewsError as exc:
                    if _passing(exc):
                        raise
                    errors.append(f"{latest['tag']}: {exc.category}")
                    log.info("cvelist: %s skipped: %s", latest["tag"], f"{exc.category}: {exc.detail}")
                cur.update(tag=latest["tag"], at=latest["at"])
        st = await vendor._state(db, DELTA_KEY)
        st.cursor = cursor()
        vendor._ok(st, DELTA_EVERY, changed)
        if errors:
            st.error = ("format: " + "; ".join(errors))[:200]
        vendor._record(db, st, meter, items=changed, parse_errors=bad + len(errors))
    except Exception as exc:  # noqa: BLE001 - this source pauses, the others go on
        await db.rollback()
        st = await vendor._state(db, DELTA_KEY)
        st.cursor = cursor()
        vendor._record(db, st, meter, exc=vendor._fail(st, exc, DELTA_EVERY))
    await db.commit()
    return changed


# ---------------------------------------------------------------- one record on demand


async def single(db: AsyncSession, cve: str, budget: list[int], ix=None) -> VendorAdvisory | None:  # noqa: ANN001
    """The cvelistV5 record of one CVE – stored (if asked within SINGLE_EVERY: what is there), else one request when the
    budget allows. A failed request raises (NewsError) and is not remembered; a 404 or an unreadable record is."""
    from app import vendor

    cve = cve.upper()
    if not CVE_ID.match(cve):
        return None
    have = await db.get(VendorAdvisory, f"cvelist:{cve}")
    row = await db.get(VendorFetch, PER_CVE + cve)
    now = datetime.now(UTC)
    if row is not None and row.last_fetch_at and now - row.last_fetch_at < SINGLE_EVERY:
        return have
    if have is not None and have.fetched_at and now - have.fetched_at < SINGLE_EVERY:
        return have  # the delta keeps it current
    if budget[0] <= 0:
        return have
    budget[0] -= 1
    body: bytes | None = None
    got: dict | str | None = None
    try:
        body = await vendor.get(raw_url(cve), db=db, conditional=False, limit=RECORD_LIMIT)
        got = await asyncio.to_thread(parse_one, body or b"{}")
    except NewsError as exc:
        # remembered as asked: a record that is not there (404) or cannot be read – a passing failure (5xx, timeout,
        # 429) is not: the CVE is asked again in the next round (security review M5)
        if not (exc.category in ("format", "too_large") or (exc.category == "http" and "404" in (exc.detail or ""))):
            raise
        log.info("cvelist: %s %s", cve, exc.category)
    row = await db.get(VendorFetch, PER_CVE + cve)
    if row is None:
        row = VendorFetch(key=PER_CVE + cve, failures=0, items=0)
        db.add(row)
    row.last_fetch_at = now
    await db.commit()
    if isinstance(got, dict):
        await vendor.store(db, [got], ix or await vendor.current_index(db))
    elif isinstance(got, str):
        await vendor.drop_advisories(db, [f"cvelist:{cve}"])
    return await db.get(VendorAdvisory, f"cvelist:{cve}", populate_existing=True)


async def backfill(db: AsyncSession, products: list[dict], ix, force: bool) -> int | None:  # noqa: ANN001
    """The CVEs of findings the NVD has not analysed (its record has no CPE configuration) and cvelistV5 was not asked
    about yet: their records, SINGLE_PER_ROUND a round, the newest first."""
    from app import vendor

    st = await vendor._state(db, SINGLE_KEY)
    now = datetime.now(UTC)
    if not vendor._due(st, now, force):
        return None
    keys = [p["key"] for p in products]
    if not keys:
        return None
    no_configs = func.coalesce(func.jsonb_array_length(VendorAdvisory.data["configs"]), 0) == 0
    asked = select(VendorFetch.key).where(VendorFetch.key == func.concat(PER_CVE, VendorAdvisory.ident), VendorFetch.last_fetch_at > now - SINGLE_EVERY)
    # a record of its own already (the delta brought it, or an earlier round): left out before the LIMIT – filtered
    # afterwards, 80 such newest CVEs kept every older one from ever being asked
    record = aliased(VendorAdvisory)
    known_q = select(record.id).where(record.id == func.concat("cvelist:", VendorAdvisory.ident))
    stmt = (
        select(VendorAdvisory.ident)
        .join(VendorAdvisoryProduct, VendorAdvisoryProduct.advisory_id == VendorAdvisory.id)
        .where(VendorAdvisoryProduct.product.in_(keys), VendorAdvisory.source == "nvd", no_configs, ~asked.exists(), ~known_q.exists())
        .order_by(VendorAdvisory.published_at.desc().nulls_last())
        .limit(SINGLE_PER_ROUND * 4)
    )
    cves = list(dict.fromkeys(await db.scalars(stmt)))
    known = set(await db.scalars(select(VendorAdvisory.ident).where(VendorAdvisory.id.in_([f"cvelist:{c}" for c in cves]))))
    cves = [c for c in cves if c not in known][:SINGLE_PER_ROUND]
    if not cves:
        st.next_fetch_at = now + DELTA_EVERY
        await db.commit()
        return None
    meter = source_health.start()
    got = 0
    budget = [len(cves)]
    try:
        for c in cves:
            if await single(db, c, budget, ix) is not None:
                got += 1
        st = await vendor._state(db, SINGLE_KEY)
        vendor._ok(st, DELTA_EVERY, got)
        vendor._record(db, st, meter, items=got)
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        st = await vendor._state(db, SINGLE_KEY)
        vendor._record(db, st, meter, exc=vendor._fail(st, exc, DELTA_EVERY))
    await db.commit()
    return got
