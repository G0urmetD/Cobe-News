"""Where Vendor News gets its data – parsers (pure, tested with trimmed real responses in tests/fixtures/vendor) and
the requests (through the news fetcher's hardened download: https only, no internal targets, DNS pinned, size and time
limits, no XML DTDs).

- Palo Alto Networks: security.paloaltonetworks.com/json/?product=<name>&sort=-updated&page=<n> – 25 advisories a page,
  per product line the affected and fixed versions ("< 11.2.4-h22, …"), an explicit list of affected versions, CVSS.
- Fortinet: the PSIRT RSS (filestore.fortinet.com/fortiguard/rss/ir.xml, the newest 50 advisories) names a CSAF file
  per advisory: affected and not affected version ranges per product, the fix per line.
- Veeam: the security KB feed (www.veeam.com/services/open/kb/security-feed, Atom, the newest ~20 KB articles) – per
  article and CVE the affected builds per product and release line ("13.1.1.18 and all earlier version 13.1 builds")
  and the fixed builds ("13.1.2 (build 13.1.2.57)"), in semi-structured HTML (parse_veeam_entry).
- NVD API 2.0 (services.nvd.nist.gov): CVE records with CPE configurations (version ranges), the CNA's affected data and
  whether CISA lists it as exploited. Without an API key 5 requests per 30 s, with one 50.
- CISA KEV (the whole JSON catalogue) – exploited vulnerabilities, also older than what the news keep.
- endoflife.date (/api/v1/products/full, one request): release lines, latest version per line, support and EOL dates.
"""

import functools
import html
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from urllib.parse import quote, urlencode

from app.news import NewsError, _date, _refuse_dtd, html_to_text
from app.news import cves as text_cves

log = logging.getLogger("cobe_news.vendor")
PAN_BASE = "https://security.paloaltonetworks.com"
FORTI_RSS = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
FORTI_HOSTS = ("filestore.fortinet.com", "fortiguard.fortinet.com", "www.fortiguard.com")
NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_PAGE = 500
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_FULL = "https://endoflife.date/api/v1/products/full"
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")
SEV = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low", "none": "info", "informational": "info"}


# U+0000 and the other C0 controls except tab, newline, carriage return: PostgreSQL's text and jsonb refuse NUL (one
# such character in an NVD description used to roll back a whole batch, every run) and none of them is ever content
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def clean(v):
    """`v` without control characters – strings, and recursively the strings (keys too) of JSON lists and objects."""
    if isinstance(v, str):
        return CONTROL.sub("", v) if CONTROL.search(v) else v
    if isinstance(v, dict):
        return {clean(k): clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [clean(x) for x in v]
    return v


def _s(v, limit: int = 2000) -> str:
    return clean(v).strip()[:limit] if isinstance(v, str) else ""


def _l(v) -> list:
    """`v` if it is a list, else empty – a field of another type than documented (1 for a list) is no crash."""
    return v if isinstance(v, list) else []


def _d(v) -> dict:
    """`v` if it is an object, else empty."""
    return v if isinstance(v, dict) else {}


# what a record of an unexpected shape raises in a parser: that record is left out (logged), not the whole answer – one
# odd Palo Alto advisory or NVD record must not pause the source (security review 0.1.16 L3)
SHAPE = (TypeError, ValueError, AttributeError, KeyError, IndexError)


def _each(items, one, what: str) -> list:
    out = []
    for x in _l(items):
        try:
            if (r := one(x)) is not None:
                out.append(r)
        except SHAPE as exc:
            log.info("vendor %s: a record of unexpected shape left out (%s)", what, type(exc).__name__)
    return out


def _shaped(fn):
    """A parser whose document has an unexpected shape fails as a NewsError("format") – like a document that is no
    JSON – instead of a TypeError the callers do not expect."""

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except SHAPE as exc:
            raise NewsError("format", f"unexpected structure ({type(exc).__name__})") from exc

    return wrapper


def severity_of(score: float | None, given: str = "") -> str:
    g = SEV.get(given.strip().lower()) if given else None
    if score is not None and score > 0:
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return g or "info"


def _score(v) -> float | None:
    if isinstance(v, bool) or not isinstance(v, int | float):
        return None
    return float(v) if 0 <= v <= 10 else None


def _json(data: bytes):
    try:
        return clean(json.loads(data))
    except (ValueError, RecursionError) as exc:
        raise NewsError("format", f"no JSON: {str(exc)[:80]}") from exc


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


# ---------------------------------------------------------------- Palo Alto Networks


def pan_url(product: str, page: int) -> str:
    return f"{PAN_BASE}/json/?{urlencode({'product': product, 'sort': '-updated', 'page': page})}"


def pan_cves(ident: str, *texts: str) -> list[str]:
    """Every CVE an advisory is about: its ID and the ones its title and text name – "Impact of Critical
    Vulnerabilities in PHP (CVE-2026-109618, CVE-2026-109619)" is filed under the first one only, but its verdict
    decides both (the NVD records of both are grouped under it)."""
    found = {ident} if CVE_ID.fullmatch(ident) else set()
    for t in texts:
        found.update(CVE_ID.findall(t or ""))
    return sorted(found)[:30]


@_shaped
def parse_pan(data: bytes) -> list[dict]:
    """One page of Palo Alto's advisory list: per advisory its lines (product + line, affected, fixed), the explicit
    list of affected versions and the texts."""
    doc = _json(data)
    if not isinstance(doc, list):
        raise NewsError("format", "not a list of advisories")
    return _each(doc[:100], _pan_one, "paloalto")


def _pan_one(a) -> dict | None:
    if not isinstance(a, dict) or not (ident := _s(a.get("ID"), 40)) or not re.fullmatch(r"(CVE-\d{4}-\d{4,7}|PAN-SA-\d{4}-\d{4})", ident):
        return None
    names, aff, fix = (a.get(k) if isinstance(a.get(k), list) else [] for k in ("version", "affected", "fixed"))
    lines = [{"name": _s(n, 80), "affected": _s(x, 600), "fixed": _s(f, 600)} for n, x, f in zip(names, aff, fix, strict=False) if isinstance(n, str)][:40]
    products = [_s(p, 80) for p in _l(a.get("product")) if isinstance(p, str)][:40]
    title = html.unescape(_s(a.get("title"), 400))
    problem = " ".join(_s(p.get("value"), 3000) for p in _l(a.get("problem")) if isinstance(p, dict))[:3000]
    solution = " ".join(_s(p.get("value"), 2000) for p in _l(a.get("solution")) if isinstance(p, dict))[:2000]
    score = _score(a.get("baseScore"))
    cves = pan_cves(ident, title, problem)
    return {
        "id": f"paloalto:{ident}",
        "source": "paloalto",
        "ident": ident,
        "title": title,
        "summary": html_to_text(problem)[:1500],
        "url": f"{PAN_BASE}/{quote(ident)}",
        "cves": cves,
        "cvss": score,
        "severity": severity_of(score, _s(a.get("baseSeverity"), 20)),
        "published_at": _date(_s(a.get("date"), 40)),
        "updated_at": _date(_s(a.get("updated"), 40)) or _date(_s(a.get("date"), 40)),
        "names": products + [ln["name"] for ln in lines],
        "data": {
            "lines": lines,
            "affected_list": [_s(x, 60) for x in _l(a.get("affected_list")) if isinstance(x, str)][:3000],
            "products": products,
            "solution": html_to_text(solution)[:1500],
        },
    }


# ---------------------------------------------------------------- Fortinet


CSAF_NS = "https://fortiguard.fortinet.com/rss/ns/csaf"


def parse_forti_rss(data: bytes) -> list[dict]:
    """The PSIRT RSS: advisory id, title, link, date and the address of its CSAF file."""
    _refuse_dtd(data)
    try:
        root = ET.fromstring(data)  # noqa: S314 - DTDs and entities are refused above
    except ET.ParseError as exc:
        raise NewsError("format", f"no XML: {str(exc)[:80]}") from exc
    channel = root.find("channel")
    out = []
    for it in (channel.findall("item") if channel is not None else [])[:100]:
        link = (it.findtext("link") or "").strip()
        m = re.search(r"FG-IR-\d{2}-\d{1,5}", link)
        csaf = (it.findtext(f"{{{CSAF_NS}}}link") or "").strip()
        if not m:
            continue
        host = re.match(r"^https://([^/]+)/", csaf)
        out.append(
            {
                "ident": m.group(0),
                "title": html.unescape((it.findtext("title") or "").strip())[:400],
                "link": link if link.startswith("https://") else f"https://fortiguard.fortinet.com/psirt/{m.group(0)}",
                "csaf": csaf if host and host.group(1) in FORTI_HOSTS else "",
                "date": _date(it.findtext("pubDate") or ""),
                "summary": html_to_text(it.findtext("description") or "")[:1500],
            }
        )
    return out


@_shaped
def parse_forti_csaf(data: bytes, item: dict) -> dict:
    """A Fortinet CSAF 2.0 file: per product family (FortiOS, FortiProxy …) the affected and not affected version
    expressions, the fix per line ("FortiOS 7.6: Upgrade to 7.6.7 or above"), CVEs and the CVSS score."""
    doc = _json(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("product_tree"), dict):
        raise NewsError("format", "no CSAF document")
    family: dict[str, str] = {}

    def walk(branches, fam: str | None) -> None:
        for b in branches if isinstance(branches, list) else []:
            if not isinstance(b, dict):
                continue
            name = _s(b.get("name"), 200)
            f = name if b.get("category") == "product_name" or (b.get("category") == "product" and fam is None and name) else fam
            prod = b.get("product") if isinstance(b.get("product"), dict) else {}
            if prod.get("product_id") and f:
                family[_s(prod.get("product_id"), 200)] = f
            walk(b.get("branches"), f if b.get("category") != "vendor" else None)

    walk(doc["product_tree"].get("branches"), None)
    products: dict[str, dict] = {}
    cves, scores, fixes = [], [], []
    for vuln in _l(doc.get("vulnerabilities")):
        if not isinstance(vuln, dict):
            continue
        if CVE_ID.fullmatch(c := _s(vuln.get("cve"), 32)):
            cves.append(c)
        for sc in _l(vuln.get("scores")):
            for k in ("cvss_v3", "cvss_v4"):
                if isinstance(sc, dict) and isinstance(sc.get(k), dict) and (v := _score(sc[k].get("baseScore"))) is not None:
                    scores.append(v)
        status = vuln.get("product_status") if isinstance(vuln.get("product_status"), dict) else {}
        for key, out_key in (("known_affected", "affected"), ("known_not_affected", "not_affected"), ("fixed", "not_affected")):
            for pid in _l(status.get(key)):
                pid = _s(pid, 200)
                fam = family.get(pid) or re.split(r"[\s/-]", pid, maxsplit=1)[0]
                products.setdefault(fam, {"affected": [], "not_affected": []})[out_key].append(pid)
        for r in _l(vuln.get("remediations")):
            if isinstance(r, dict) and r.get("category") == "vendor_fix":
                fixes.append(_s(r.get("details"), 2000))
    tracking = _d(_d(doc.get("document")).get("tracking"))
    score = max(scores) if scores else None
    for v in products.values():
        v["affected"] = list(dict.fromkeys(v["affected"]))[:60]
        v["not_affected"] = list(dict.fromkeys(v["not_affected"]))[:60]
    title = _s(_d(doc.get("document")).get("title"), 400) or item.get("title") or item["ident"]
    return {
        "id": f"fortinet:{item['ident']}",
        "source": "fortinet",
        "ident": item["ident"],
        "title": title,
        "summary": item.get("summary") or "",
        "url": item.get("link") or f"https://fortiguard.fortinet.com/psirt/{item['ident']}",
        "cves": sorted(set(cves))[:30],
        "cvss": score,
        "severity": severity_of(score),
        "published_at": _date(_s(tracking.get("initial_release_date"), 40)) or item.get("date"),
        "updated_at": _date(_s(tracking.get("current_release_date"), 40)) or item.get("date"),
        "names": list(products),
        "data": {"products": products, "remediation": "\n".join(fixes)[:4000], "rev": _s(tracking.get("version"), 20)},
    }


# ---------------------------------------------------------------- Veeam (security KB feed)


VEEAM_FEED = "https://www.veeam.com/services/open/kb/security-feed"
ATOM = "{http://www.w3.org/2005/Atom}"
VEEAM_KB = re.compile(r"^https://www\.veeam\.com/kb(\d{3,6})/?$", re.I)
_VER = r"\d{1,3}(?:\.\d{1,6}){1,4}(?:\s*P\d{8})?"  # 12.3.2.4934, 11.0.1.1261 P20240304
_REL = rf"{_VER}(?:\s+(?:P|Patch)\s?\d{{1,3}})?"  # a release name: 12.3.2 P4, 13.1 Patch 1
_PRODUCT = r"(?:Veeam|Kasten)\b[^\n|]{1,120}?"  # not the "Product: Veeam Backup & Replication | 12 | 12.1" line
# "Veeam Backup & Replication 13.1.1.18 and all earlier version 13.1 builds." – also "… 12.3.2 P3 (build 12.3.2.4854) and
# older builds", "… and all earlier version 13 and 6 builds", "… and all earlier versions of 12 builds"; an article-wide
# one starts "All vulnerabilities disclosed in this article affect …" or "Affect only …"
_V_AFFECTED = re.compile(
    rf"^(?P<all>All vulnerabilities (?:disclosed|documented|listed) in this article affect(?: only)?\s+|Affect(?:s)? only\s+)?"
    rf"(?P<product>{_PRODUCT})\s+(?P<rel>{_REL})(?:\s*\(build\s*(?P<build>{_VER})\))?"
    rf"(?P<tail>\s+and\s+(?:all\s+)?(?:earlier|older|prior)\b[^\n]{{0,80}}?)?\s*\.?$",
    re.I,
)
# "Veeam Backup & Replication 13.1.2 (build 13.1.2.57)", "Veeam Service Provider Console 9.3.0.35057"; article-wide:
# "Are resolved in …", "All vulnerabilities documented in this article were resolved in …"
_V_FIXED = re.compile(
    rf"^(?P<all>(?:Are|is|were) resolved in\s+|All vulnerabilities (?:disclosed|documented|listed) in this article were resolved in\s+)?"
    rf"(?P<product>{_PRODUCT})\s+(?P<rel>{_REL})(?:\s*\(build\s*(?P<build>{_VER})\))?\s*\.?$",
    re.I,
)
_V_SOLUTION = re.compile(r"^(?:Solution|(?:This|These) vulnerabilit(?:y|ies) (?:was|were|is|are) (?:fixed|resolved) starting\b.*)$", re.I)
_V_CVE_HEAD = re.compile(r"^(CVE-\d{4}-\d{4,7})$")
_V_SCORE = re.compile(r"CVSS(?:\s*v(?P<ver>\d(?:\.\d)?))?\s+Score:\s*(?P<score>\d{1,2}(?:\.\d)?)(?:\s*CVSS:?\s*(?P<vector>(?:\d\.\d/)?[A-Z]{1,2}:[A-Z](?:/[A-Z]{1,2}:[A-Z])+))?", re.I)
_V_SEVERITY = re.compile(r"^Severity:\s*(Critical|High|Medium|Moderate|Low)\b", re.I)
_V_OLDER_NOT = re.compile(r"\bolder versions?\b[^\n]{0,60}\bare not affected\b", re.I)
_V_OLDER_UNTESTED = re.compile(r"\bunsupported (?:product )?versions? (?:were|are) not tested\b[^\n]{0,80}\b(?:likely affected|considered vulnerable)\b", re.I)
_V_LINE_NOT = re.compile(r"\b(?:versions?\s+(?P<a>\d{1,3}(?:\.\d{1,3})?)(?:\.x)?\s+(?:is|are)\s+not\s+affected|do(?:es)?\s+not\s+affect\s+any\b[^\n]{0,60}?\bversion\s+(?P<b>\d{1,3}(?:\.\d{1,3})?)(?:\.x)?\s+builds?)\b", re.I)
_V_NONE = re.compile(r"^Veeam products\b[^\n]{0,80}\bare not affected\b", re.I)
_V_LABELS = re.compile(r"^(?:Severity|CVSS|Affected Deployment Type|Source|Note|Affected Product|Solution|Issue Details|Mitigation)\b", re.I)
VEEAM_SEV = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low"}
VEEAM_MAX_ISSUES = 40


def _veeam_product(name: str) -> str:
    """'Veeam Backup Enterprise Manager (Veeam Backup & Replication)' as written, spaces collapsed."""
    return re.sub(r"\s+", " ", name).strip(" ,;:")[:120]


def _veeam_lines(tail: str) -> list[str]:
    """'and all earlier version 13 and 6 builds' → ['13', '6']; 'and older builds' → [] (every earlier build)."""
    return list(dict.fromkeys(re.findall(r"\b(\d{1,3}(?:\.\d{1,3})?)(?:\.x)?\b", tail or "")))[:6]


def _veeam_text_lines(content: str) -> list[str]:
    return [ln.strip() for ln in html_to_text(content).splitlines() if ln.strip()][:3000]


def parse_veeam_entry(title: str, link: str, content: str, published: datetime | None = None, updated: datetime | None = None) -> dict | None:
    """One KB article of Veeam's security feed as an advisory – None for what is not one (the running "List of
    Security Fixes and Improvements" pages: every fix of every build, no affected ranges) or a link that is no KB.

    Per CVE ("issue") the affected statements per product (up to a build, within release lines), the fixed builds, the
    notes on other lines ("Older versions (e.g., 12.x) are not affected", "Version 13 is not affected", "Unsupported
    product versions … should be considered vulnerable"), CVSS and severity. Statements for the whole article ("All
    vulnerabilities disclosed in this article affect …", "These vulnerabilities were fixed starting with …") apply to
    every CVE that has none of its own. Untrusted text: only matched, never interpreted; everything is cut to size."""
    m = VEEAM_KB.match((link or "").strip())
    title = re.sub(r"\s+", " ", html.unescape(title or "")).strip()[:400]
    if not m or not title or re.match(r"(?i)^list of security fixes", title):
        return None
    kb = f"KB{int(m.group(1))}"
    lines = _veeam_text_lines(content)
    meta: dict[str, str] = {}
    for i, ln in enumerate(lines[:40]):
        if ln.rstrip(":") in ("KB ID", "Product", "Published", "Last Modified") and i + 1 < len(lines):
            meta.setdefault(ln.rstrip(":"), lines[i + 1][:200])
    meta_product = _veeam_product(meta.get("Product", "").split("|")[0]) if meta.get("Product") else ""
    issues: list[dict] = []
    glob: dict = {"affected": [], "fixed": [], "older": "", "not_lines": []}
    cur: dict | None = None
    in_solution = solution_all = False
    none_affected = mitigation = False

    def target(article_wide: bool) -> dict:
        return glob if article_wide or cur is None else cur

    for ln in lines:
        if head := _V_CVE_HEAD.match(ln):
            known = next((x for x in issues if x["cves"] == [head.group(1)]), None)
            if known is None and len(issues) < VEEAM_MAX_ISSUES:
                known = {"cves": [head.group(1)], "affected": [], "fixed": [], "older": "", "not_lines": [], "cvss": None, "vector": "", "severity": "", "text": "", "deployment": ""}
                issues.append(known)
            cur, in_solution, solution_all = known, False, False
            continue
        if re.match(r"(?i)^CVE-\d{4}-\d{4,7} Impact Mitigation$|^Mitigation$", ln):
            mitigation, in_solution = True, False
            continue
        if _V_NONE.match(ln):
            none_affected = True
            continue
        if _V_SOLUTION.match(ln):
            in_solution, solution_all = True, bool(re.match(r"(?i)^these\b", ln)) or cur is None
            continue
        if (fx := _V_FIXED.match(ln)) and (in_solution or fx.group("all")):
            row = {"product": _veeam_product(fx.group("product")), "name": re.sub(r"\s+", " ", fx.group("rel")), "build": re.sub(r"\s+", " ", fx.group("build") or fx.group("rel"))}
            t = target(bool(fx.group("all")) or solution_all)
            if row not in t["fixed"] and len(t["fixed"]) < 20:
                t["fixed"].append(row)
            continue
        in_solution = False
        if af := _V_AFFECTED.match(ln):
            row = {
                "product": _veeam_product(af.group("product")),
                "upto": re.sub(r"\s+", " ", af.group("build") or af.group("rel")),
                "lines": _veeam_lines(af.group("tail") or ""),
                "earlier": bool(af.group("tail")),
            }
            t = target(bool(af.group("all")))
            if row not in t["affected"] and len(t["affected"]) < 20:
                t["affected"].append(row)
            continue
        t = target(cur is None)
        if _V_OLDER_UNTESTED.search(ln):
            t["older"] = "affected"
        elif _V_OLDER_NOT.search(ln):
            t["older"] = "not_affected"
        for lm in _V_LINE_NOT.finditer(ln):
            line = lm.group("a") or lm.group("b")
            if line not in t["not_lines"]:
                t["not_lines"].append(line)
        if cur is None:
            continue
        if sc := _V_SCORE.search(ln):
            score = float(sc.group("score"))
            if 0 <= score <= 10:
                cur["cvss"], cur["vector"] = score, (sc.group("vector") or "")[:120]
                cur["cvss_version"] = sc.group("ver") or ""
        elif sv := _V_SEVERITY.match(ln):
            cur["severity"] = VEEAM_SEV[sv.group(1).lower()]
        elif ln.lower().startswith("affected deployment type:"):
            cur["deployment"] = ln.split(":", 1)[1].strip()[:200]
        elif not cur["text"] and not _V_LABELS.match(ln) and len(ln) > 30:
            cur["text"] = ln[:600]
    if not issues and (glob["affected"] or glob["fixed"]):
        issues.append({"cves": [], "affected": [], "fixed": [], "older": "", "not_lines": [], "cvss": None, "vector": "", "severity": "", "text": "", "deployment": ""})
    for x in issues:  # what the article says for all of them, where a CVE says nothing of its own
        x["affected"] = x["affected"] or list(glob["affected"])
        x["fixed"] = x["fixed"] or list(glob["fixed"])
        x["older"] = x["older"] or glob["older"]
        x["not_lines"] = list(dict.fromkeys([*x["not_lines"], *glob["not_lines"]]))[:6]
    body = "\n".join(lines)
    cve_ids = text_cves(f"{title}\n{body}")
    scores = [x["cvss"] for x in issues if x["cvss"] is not None]
    if not scores and (sc := _V_SCORE.search(body)):
        scores = [float(sc.group("score"))] if 0 <= float(sc.group("score")) <= 10 else []
    score = max(scores) if scores else None
    given = max((x["severity"] for x in issues if x["severity"]), key=lambda s: ["low", "medium", "high", "critical"].index(s), default="")
    products = list(dict.fromkeys([*(r["product"] for x in issues for r in x["affected"] + x["fixed"]), *([meta_product] if meta_product else [])]))[:20]
    texts = [x["text"] for x in issues if x["text"]]
    summary = " ".join(dict.fromkeys(texts))[:1500] or next((ln for ln in lines if len(ln) > 60 and not ln.startswith("Veeam® is committed")), "")[:1500]
    pub = _date(meta.get("Published", "")) or published
    upd = max((d for d in (_date(meta.get("Last Modified", "")), updated, pub) if d is not None), default=None)
    return {
        "id": f"veeam:{kb}",
        "source": "veeam",
        "ident": kb,
        "title": title,
        "summary": summary,
        "url": f"https://www.veeam.com/{kb.lower()}",
        "cves": cve_ids,
        "cvss": score,
        "severity": severity_of(score, given),
        "published_at": pub,
        "updated_at": upd,
        "names": products,
        "data": {"issues": issues, "products": products, "none_affected": none_affected, "mitigation": mitigation},
    }


def parse_veeam(data: bytes) -> list[dict]:
    """The security KB feed (Atom): every KB article that is an advisory (see parse_veeam_entry)."""
    _refuse_dtd(data)
    try:
        root = ET.fromstring(data)  # noqa: S314 - DTDs and entities are refused above
    except ET.ParseError as exc:
        raise NewsError("format", f"no XML: {str(exc)[:80]}") from exc
    if root.tag != f"{ATOM}feed":
        raise NewsError("format", "not an Atom feed")
    out = []
    for e in root.findall(f"{ATOM}entry")[:100]:
        link = next((ln.get("href") or "" for ln in e.findall(f"{ATOM}link") if ln.get("rel") in (None, "alternate")), "") or (e.findtext(f"{ATOM}id") or "")
        a = parse_veeam_entry(
            e.findtext(f"{ATOM}title") or "",
            link,
            e.findtext(f"{ATOM}content") or e.findtext(f"{ATOM}summary") or "",
            _date(e.findtext(f"{ATOM}published") or ""),
            _date(e.findtext(f"{ATOM}updated") or ""),
        )
        if a is not None:
            out.append(a)
    return out


# ---------------------------------------------------------------- NVD


def nvd_url(**params) -> str:
    return f"{NVD_CVES}?{urlencode({k: v for k, v in params.items() if v is not None}, safe=':*')}"


def nvd_time(d: datetime) -> str:
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")


def _nvd_metrics(m: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = [r for r in _l(m.get(key)) if isinstance(r, dict)]
        rows.sort(key=lambda r: r.get("type") != "Primary")
        for r in rows:
            d = _d(r.get("cvssData"))
            if (s := _score(d.get("baseScore"))) is not None:
                return s, _s(d.get("baseSeverity") or r.get("baseSeverity"), 20)
    return None, ""


def _trim_configs(configs) -> list:
    out = []
    for cfg in configs if isinstance(configs, list) else []:
        nodes = []
        for node in _l(cfg.get("nodes")) if isinstance(cfg, dict) else []:
            ms = []
            for m in _l(node.get("cpeMatch")) if isinstance(node, dict) else []:
                if isinstance(m, dict) and m.get("vulnerable") and isinstance(m.get("criteria"), str):
                    ms.append({"vulnerable": True, "criteria": m["criteria"][:300], **{k: _s(m[k], 64) for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if m.get(k)}})
            if ms:
                nodes.append({"cpeMatch": ms[:400]})
        if nodes:
            out.append({"nodes": nodes})
    return out[:50]


def _trim_cna(affected) -> list:
    out = []
    for src in affected if isinstance(affected, list) else []:
        rows = []
        for a in _l(src.get("affectedData")) if isinstance(src, dict) else []:
            if not isinstance(a, dict):
                continue
            versions = []
            for x in _l(a.get("versions")):
                if isinstance(x, dict):
                    row = {k: _s(x[k], 64) for k in ("version", "lessThan", "lessThanOrEqual", "status", "versionType") if isinstance(x.get(k), str)}
                    ch = [{"at": _s(c.get("at"), 64), "status": _s(c.get("status"), 20)} for c in _l(x.get("changes")) if isinstance(c, dict)][:60]
                    if ch:
                        row["changes"] = ch
                    versions.append(row)
            rows.append({"vendor": _s(a.get("vendor"), 120), "product": _s(a.get("product"), 200), "defaultStatus": _s(a.get("defaultStatus"), 20), "versions": versions[:200]})
        if rows:
            out.append({"affectedData": rows[:60]})
    return out[:10]


def _cwes(weaknesses) -> list[str]:
    """The weaknesses of a CVE record ("CWE-79"), primary first – for a readable title (vendor_titles)."""
    rows = [w for w in weaknesses if isinstance(w, dict)] if isinstance(weaknesses, list) else []
    rows.sort(key=lambda w: w.get("type") != "Primary")
    out: list[str] = []
    for w in rows:
        for d in _l(w.get("description")):
            v = _s(d.get("value"), 20) if isinstance(d, dict) else ""
            if re.fullmatch(r"CWE-\d{1,5}", v) and v not in out:
                out.append(v)
    return out[:5]


@_shaped
def parse_nvd(data: bytes, rejected: list[str] | None = None) -> tuple[int, list[dict]]:
    """A page of NVD CVE records: (totalResults, advisories). `rejected`: the ids of rejected records go there (they
    are no advisory – a stored copy is removed)."""
    doc = _json(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise NewsError("format", "no NVD CVE list")
    out = _each(doc["vulnerabilities"], lambda item: _nvd_one(item, rejected), "nvd")
    total = doc.get("totalResults")
    return (total if isinstance(total, int) else len(out)), out


def _nvd_one(item, rejected: list[str] | None) -> dict | None:
    c = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(c, dict) or not CVE_ID.fullmatch(cid := _s(c.get("id"), 32)):
        return None
    if _s(c.get("vulnStatus"), 30) == "Rejected":
        if rejected is not None:
            rejected.append(f"nvd:{cid}")
        return None
    desc = next((_s(d.get("value"), 4000) for d in _l(c.get("descriptions")) if isinstance(d, dict) and d.get("lang") == "en"), "")
    score, given = _nvd_metrics(_d(c.get("metrics")))
    kev = _s(c.get("cisaExploitAdd"), 10)
    short = re.sub(r"\s+", " ", desc)
    return {
        "id": f"nvd:{cid}",
        "source": "nvd",
        "ident": cid,
        "title": _s(c.get("cisaVulnerabilityName"), 300) or (short[:180] + (" …" if len(short) > 180 else "")),
        "summary": desc[:1500],
        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
        "cves": [cid],
        "cvss": score,
        "severity": severity_of(score, given),
        "exploited": bool(kev),
        "published_at": _date(_s(c.get("published"), 40)),
        "updated_at": _date(_s(c.get("lastModified"), 40)),
        "data": {
            "configs": _trim_configs(c.get("configurations")),
            "cna": _trim_cna(c.get("affected")),
            "desc": desc[:1500],
            "cwe": _cwes(c.get("weaknesses")),
            "status": _s(c.get("vulnStatus"), 30),
            "kev": {"added": kev, "due": _s(c.get("cisaActionDue"), 10)} if kev else None,
        },
    }


@_shaped
def parse_cpes(data: bytes) -> list[dict]:
    """The NVD CPE dictionary's answer to a search: distinct part:vendor:product with a title."""
    doc = _json(data)
    out: dict[str, dict] = {}
    for p in _l(doc.get("products")) if isinstance(doc, dict) else []:
        cpe = _d(p.get("cpe")) if isinstance(p, dict) else {}
        name = _s(cpe.get("cpeName"), 300)
        if not name.startswith("cpe:2.3:") or cpe.get("deprecated"):
            continue
        parts = re.split(r"(?<!\\):", name)
        if len(parts) < 5:
            continue
        key = ":".join(parts[2:5])
        title = next((_s(t.get("title"), 200) for t in _l(cpe.get("titles")) if isinstance(t, dict) and t.get("lang") == "en"), "")
        title = re.sub(r"\s+\S*\d[\w.\-]*$", "", title) or title  # "Citrix NetScaler 13.1" → "Citrix NetScaler"
        out.setdefault(key, {"cpe": key, "title": title, "vendor": parts[3].replace("_", " "), "product": parts[4].replace("_", " ")})
    return list(out.values())[:50]


# ---------------------------------------------------------------- KEV, endoflife.date


@_shaped
def parse_kev(data: bytes) -> list[dict]:
    doc = _json(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise NewsError("format", "no KEV catalog")
    out = []
    for v in doc["vulnerabilities"]:
        if isinstance(v, dict) and CVE_ID.fullmatch(cve := _s(v.get("cveID"), 32).upper()):
            out.append(
                {
                    "cve": cve,
                    "vendor": _s(v.get("vendorProject"), 100),
                    "product": _s(v.get("product"), 150),
                    "name": _s(v.get("vulnerabilityName"), 300),
                    "date_added": _s(v.get("dateAdded"), 10),
                    "due": _s(v.get("dueDate"), 10),
                    "ransomware": _s(v.get("knownRansomwareCampaignUse"), 20).lower() == "known",
                }
            )
    return out


def parse_eol(data: bytes) -> dict:
    doc = _json(data)
    if not isinstance(doc, dict) or not isinstance(doc.get("result"), list) or len(doc["result"]) < 10:
        raise NewsError("format", "not endoflife.date's product list")
    return doc
