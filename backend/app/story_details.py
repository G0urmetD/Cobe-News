"""Details aus der Quelle: the structured advisory behind a story – affected products with version ranges and fixed
versions, CVSS, CVEs, exploited, workaround/mitigation, revision ("Stand") – fetched once per advisory, kept per
story, refreshed while the story is young (and at once when its title changes, e.g. "[UPDATE]").

Per source:
- BSI CERT-Bund (WID): CSAF 2.0 – the RSS link's WID-SEC-YYYY-NNNN is the document
  /.well-known/csaf/white/YYYY/wid-sec-w-YYYY-NNNN.json (products with "<19.5.1"-style ranges, fixed versions, CVEs,
  revision history; no CVSS – that comes from the NVD for its first CVEs)
- Siemens ProductCERT: CSAF 2.0 (/productcert/csaf/ssa-NNNNNN.json)
- Cisco PSIRT: CSAF 2.0 (/security/center/contentjson/CiscoSecurityAdvisory/<id>/csaf/<id>.json)
- Fortinet PSIRT: CSAF 2.0 – its address from the PSIRT RSS
- Palo Alto Networks: the advisory as CVE 5 JSON (/json/<id>)
- Veeam (www.veeam.com/kbNNNN, the built-in source "veeam"): the KB article is the story's own text – read with Vendor
  News' parser (vendor_sources.parse_veeam_entry), no request
- CISA KEV / ENISA EUVD: the story itself (exploited, due date, EPSS) plus the NVD for ranges and CVSS
- any other story with CVEs: the NVD (marked "aus NVD") – CVSS, CPE ranges, the fix version; for a CVE the NVD has not
  analysed yet (no record, no CPE configuration) the cvelistV5 record (app/cvelist.py): the CNA's ranges, CISA's CVSS,
  SSVC and KEV ("ergänzt aus der CVE-Liste")

Everything goes through Vendor News' request path (the news fetcher's hardened download, per-host gaps, NVD rate
limit). CSAF advisories are also stored as Vendor News advisories (`csaf:<id>`), so a followed product gets a finding
– and a notification – from a BSI, Siemens or Cisco advisory as well; the CSAF providers (app/csaf_providers.py) store
the same documents under the same id (csaf_advisory), so one advisory is one record however it came."""

import asyncio
import hashlib
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import Text, and_, cast, literal, or_, select, true, update
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import array as pg_array
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app import db as dbm
from app import settings as settings_store
from app import vendor
from app import vendor_sources as src
from app.models import NewsItem, NewsSource, StoryDetail, VendorAdvisory, VendorFetch, VendorFollow, VendorKev, VendorVersion
from app.news import NewsError, _date, html_to_text
from app.vendor_match import evaluate, ranges_of, worst
from app.vendor_versions import parse

log = logging.getLogger("cobe_news.details")

CSAF_LIMIT = 4 * 1024 * 1024
FRESH = timedelta(days=30)  # younger stories: the CSAF is asked again daily (conditional) – an UPDATE shows up
CSAF_EVERY = timedelta(hours=24)
NVD_EVERY = timedelta(days=7)
MAX_CVES = 3  # NVD lookups per story (CVSS and ranges of the first ones)
MAX_PRODUCTS = 25
MAX_VERSIONS = 400
CSAF_PER_ROUND = 25
NVD_PER_ROUND = (8, 40)  # without / with an API key
CVELIST_PER_ROUND = 15  # cvelistV5 records of CVEs the NVD has not analysed (raw.githubusercontent.com, one each)
WID = re.compile(r"WID-SEC-(\d{4})-(\d{1,6})", re.I)
SIEMENS = re.compile(r"\b(ssa-\d{6})\b", re.I)
CISCO = re.compile(r"/CiscoSecurityAdvisory/(cisco-sa-[A-Za-z0-9_-]{4,80})", re.I)
PAN = re.compile(r"^https://security\.paloaltonetworks\.com/((?:CVE-\d{4}-\d{4,7})|(?:PAN-SA-\d{4}-\d{4}))", re.I)
FORTI = re.compile(r"(FG-IR-\d{2}-\d{1,5})", re.I)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")
PUBLISHER = {
    "bsi": "BSI (CSAF)",
    "siemens": "Siemens ProductCERT (CSAF)",
    "cisco": "Cisco PSIRT (CSAF)",
    "fortinet": "Fortinet PSIRT (CSAF)",
    "paloalto": "Palo Alto Networks",
    "veeam": "Veeam Security (KB)",
    "nvd": "NVD",
    "kev": "CISA KEV",
    "euvd": "ENISA EUVD",
}
PROVIDER_KINDS = ("siemens", "cisco")  # story kinds whose documents come from a CSAF provider of csaf.yaml (same key)
DOCUMENT_KINDS = ("bsi", "siemens", "cisco", "fortinet", "paloalto")  # one request for the advisory's own document


# ---------------------------------------------------------------- where the details of a story are


def plan(source_key: str, url: str, cves: list[str]) -> tuple[str, str, str | None]:
    """(kind, ident, document URL) for a story – kind: bsi | siemens | cisco | fortinet | paloalto | veeam | kev | euvd | nvd | none."""
    if m := WID.search(url):
        y, n = m.group(1), m.group(2)
        return "bsi", f"WID-SEC-W-{y}-{n}", f"https://wid.cert-bund.de/.well-known/csaf/white/{y}/wid-sec-w-{y}-{n}.json"
    host = (urlsplit(url).hostname or "").lower()
    if host == "cert-portal.siemens.com" and (m := SIEMENS.search(url)):
        sid = m.group(1).lower()
        return "siemens", sid.upper(), f"https://cert-portal.siemens.com/productcert/csaf/{sid}.json"
    if host == "sec.cloudapps.cisco.com" and (m := CISCO.search(url)):
        cid = m.group(1)
        return "cisco", cid, f"https://sec.cloudapps.cisco.com/security/center/contentjson/CiscoSecurityAdvisory/{cid}/csaf/{cid}.json"
    if (m := src.VEEAM_KB.match(url)) is not None:
        return "veeam", f"KB{int(m.group(1))}", None  # the story's text is the KB article
    if (m := PAN.match(url)) is not None:
        return "paloalto", m.group(1).upper(), f"https://security.paloaltonetworks.com/json/{m.group(1).upper()}"
    if host in ("fortiguard.fortinet.com", "www.fortiguard.com") and (m := FORTI.search(url)):
        return "fortinet", m.group(1).upper(), None  # the CSAF address comes from the PSIRT RSS
    if source_key == "cisa-kev" and cves:
        return "kev", cves[0], None
    if source_key == "enisa-euvd" and cves:
        return "euvd", cves[0], None
    if cves:
        return "nvd", cves[0], None
    return "none", "", None


# ---------------------------------------------------------------- version ranges


# ---------------------------------------------------------------- CSAF 2.0


_l, _d = src._l, src._d  # a field of another type than documented is no crash (security review 0.1.16 L3)


def _s(v, n: int = 400) -> str:
    return src.clean(v).strip()[:n] if isinstance(v, str) else ""


def _sortkey(text: str):
    v = parse("generic", re.sub(r"^[<>=]+", "", text))
    return v.key if v else (9999,)


STORE_PRODUCTS = 300  # products of a CSAF document kept for Vendor News (the details show MAX_PRODUCTS)


@src._shaped
def parse_csaf(data: bytes, kind: str, max_products: int = MAX_PRODUCTS) -> dict:
    """A CSAF 2.0 advisory as details: products (vendor, name, CPE, affected ranges / versions, fixed versions), CVSS,
    CVEs, remediations, revision, its TLP label and the address of its advisory page."""
    try:
        doc = src.clean(json.loads(data))
    except (ValueError, RecursionError) as exc:
        raise NewsError("format", f"no JSON: {str(exc)[:80]}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("document"), dict) or not isinstance(doc.get("product_tree"), dict):
        raise NewsError("format", "no CSAF document")
    pmap: dict[str, dict] = {}

    def walk(branches, ctx: dict) -> None:
        for b in branches if isinstance(branches, list) else []:
            if not isinstance(b, dict):
                continue
            cat, name = b.get("category"), _s(b.get("name"), 200)
            c = dict(ctx)
            if cat == "vendor":
                c = {"vendor": name}
            elif cat in ("product_name", "product_family", "product"):  # Fortinet writes "product"
                c["product"] = name if cat == "product_name" or "product" not in c or ctx.get("family") else c["product"]
                c["family"] = cat == "product_family"
            elif cat in ("product_version", "product_version_range", "service_pack", "patch_level"):
                c["version"] = name
                c["vcat"] = cat
            prod = b.get("product") if isinstance(b.get("product"), dict) else None
            if prod and prod.get("product_id"):
                helper = prod.get("product_identification_helper") if isinstance(prod.get("product_identification_helper"), dict) else {}
                pmap[_s(prod["product_id"], 120)] = {**c, "cpe": _s(helper.get("cpe"), 200), "full": _s(prod.get("name"), 300)}
            walk(b.get("branches"), c)

    walk(doc["product_tree"].get("branches"), {})
    for fp in _l(doc["product_tree"].get("full_product_names")):
        if isinstance(fp, dict) and fp.get("product_id"):
            pmap.setdefault(_s(fp["product_id"], 120), {"product": _s(fp.get("name"), 200), "full": _s(fp.get("name"), 300)})
    for rel in _l(doc["product_tree"].get("relationships")):
        fpn = rel.get("full_product_name") if isinstance(rel, dict) else None
        if isinstance(fpn, dict) and fpn.get("product_id") and (base := pmap.get(_s(rel.get("product_reference"), 120))):
            pmap.setdefault(_s(fpn["product_id"], 120), dict(base))
    for p in pmap.values():
        if p.get("version") and p.get("product"):
            p["version"] = re.sub(rf"^{re.escape(p['product'])}\s*/?\s*", "", p["version"]).strip() or p["version"]
    products: dict[tuple[str, str], dict] = {}

    def entry(p: dict, pid: str) -> dict:
        name = p.get("product") or p.get("full") or pid
        e = products.setdefault((p.get("vendor") or "", name), {"vendor": p.get("vendor") or "", "name": name, "cpe": "", "affected": set(), "fixed": set(), "not_affected": set()})
        cpe = p.get("cpe") or ""
        if cpe and not e["cpe"]:
            parts = cpe.replace("cpe:2.3:", "").replace("cpe:/", "").split(":")
            e["cpe"] = ":".join(parts[:3]) if len(parts) >= 3 else ""
        return e

    cves, cvss, rems, threats = [], [], [], []
    for vuln in _l(doc.get("vulnerabilities")):
        if not isinstance(vuln, dict):
            continue
        if CVE_ID.fullmatch(c := _s(vuln.get("cve"), 32)):
            cves.append(c)
        st = vuln.get("product_status") if isinstance(vuln.get("product_status"), dict) else {}
        for key, slot in (("known_affected", "affected"), ("first_affected", "affected"), ("last_affected", "affected"), ("fixed", "fixed"), ("first_fixed", "fixed"), ("known_not_affected", "not_affected")):
            for pid in _l(st.get(key)):
                p = pmap.get(_s(pid, 120))
                if not p:
                    continue
                e = entry(p, pid)
                ver = p.get("version")
                if slot == "affected":
                    e["affected"].add(ver or "*")
                elif ver:
                    e[slot].add(ver)
        for sc in _l(vuln.get("scores")):
            for k in ("cvss_v4", "cvss_v3"):
                d = sc.get(k) if isinstance(sc, dict) else None
                if isinstance(d, dict) and isinstance(d.get("baseScore"), int | float):
                    cvss.append({"score": float(d["baseScore"]), "temporal": float(d["temporalScore"]) if isinstance(d.get("temporalScore"), int | float) else None, "vector": _s(d.get("vectorString"), 200), "version": _s(d.get("version"), 5)})
                    break
        for r in _l(vuln.get("remediations")):
            if isinstance(r, dict) and r.get("category") in ("vendor_fix", "workaround", "mitigation", "no_fix_planned", "none_available"):
                rems.append({"category": r["category"], "text": _s(r.get("details"), 400), "url": _s(r.get("url"), 400) if _s(r.get("url"), 400).startswith("https://") else ""})
        for t in _l(vuln.get("threats")):
            if isinstance(t, dict) and t.get("category") == "exploit_status":
                threats.append(_s(t.get("details"), 200))
    for pid, p in pmap.items():
        # the BSI names the fixed version of each range as its own product "<id>-fixed" (with a CPE)
        if pid.endswith("-fixed") and p.get("version") and (p.get("vendor") or "", p.get("product") or p.get("full") or pid) in products:
            e = entry(p, pid)
            e["fixed"].add(p["version"])
    tracking = _d(doc["document"].get("tracking"))
    hist = [h for h in _l(tracking.get("revision_history")) if isinstance(h, dict)]
    hist.sort(key=lambda h: _s(h.get("date"), 40))
    notes = {(_s(n.get("category"), 30), _s(n.get("title"), 80)): _s(n.get("text"), 600) for n in _l(doc["document"].get("notes")) if isinstance(n, dict)}
    summary = next((t for (c, _), t in notes.items() if c == "summary"), "")
    plist = []
    for e in products.values():
        aff = sorted(e["affected"], key=_sortkey, reverse=True)[:MAX_VERSIONS]
        plist.append(
            {
                "vendor": e["vendor"][:100],
                "name": e["name"][:150],
                "cpe": e["cpe"],
                "affected": [r for x in aff for r in ranges_of(x)],
                "fixed": sorted(e["fixed"], key=_sortkey, reverse=True)[:60],
                "not_affected": sorted(e["not_affected"], key=_sortkey, reverse=True)[:60],
            }
        )
    plist.sort(key=lambda p: (not p["affected"], p["vendor"], p["name"]))
    tlp = _s(_d(_d(doc["document"].get("distribution")).get("tlp")).get("label"), 20).upper()
    page = next((u for r in _l(doc["document"].get("references")) if isinstance(r, dict) and r.get("category") == "self" and (u := _s(r.get("url"), 400)).startswith("https://")), "")
    # remote: a CVSS vector with network access – or the BSI's words ("entfernter Angreifer")
    remote = any("AV:N" in c["vector"] for c in cvss) or bool(re.search(r"\bentfernte[rn]?\b|\bremote\b", summary, re.I)) or None
    rems = list({(r["category"], r["text"]): r for r in rems}.values())[:6]
    return {
        "kind": kind,
        "publisher": PUBLISHER.get(kind, _s(_d(doc["document"].get("publisher")).get("name"), 80)),
        # the publisher's namespace (a URL of its own domain): who speaks – checked against a CSAF provider's hosts
        "namespace": _s(_d(doc["document"].get("publisher")).get("namespace"), 200),
        "id": _s(tracking.get("id"), 120),
        "title": _s(doc["document"].get("title"), 300),
        "severity_text": _s(_d(doc["document"].get("aggregate_severity")).get("text"), 30),
        "summary": summary[:600],
        "products": plist[:max_products],
        "more_products": max(0, len(plist) - max_products),
        "tlp": tlp,
        "page": page,
        "cves": sorted(set(cves))[:60],
        "cvss": sorted(cvss, key=lambda c: -c["score"])[:1],
        # "Exploit Status: nicht bekannt", "keine Ausnutzung bekannt", "hasn't been exploited" – denied, not exploited
        "exploited": any(re.search(r"exploit|ausgenutzt|in the wild", t, re.I) and not re.search(r"\bno\b|\bnot\b|\bnever\b|n['’]t\b|\bnicht\b|\bnie\b|\bkein", t, re.I) for t in threats),
        "remote": remote,
        "mitigation": any(r["category"] in ("workaround", "mitigation") for r in rems) or None,
        "remediations": rems,
        "revision": {
            "current": _s(tracking.get("current_release_date"), 40),
            "initial": _s(tracking.get("initial_release_date"), 40),
            "version": _s(tracking.get("version"), 20),
            "summary": _s(hist[-1].get("summary"), 200) if hist else "",
            "count": len(hist),
        },
    }


# ---------------------------------------------------------------- CVE 5 (Palo Alto)


@src._shaped
def parse_cve5(data: bytes) -> dict:
    try:
        doc = src.clean(json.loads(data))
    except (ValueError, RecursionError) as exc:
        raise NewsError("format", f"no JSON: {str(exc)[:80]}") from exc
    cna = (_d(doc.get("containers")).get("cna") or {}) if isinstance(doc, dict) else {}
    if not isinstance(cna, dict) or not isinstance(cna.get("affected"), list):
        raise NewsError("format", "no CVE record")
    meta = _d(doc.get("cveMetadata"))
    plist, cna_rows = [], []
    for a in cna["affected"]:
        if not isinstance(a, dict):
            continue
        versions = [x for x in _l(a.get("versions")) if isinstance(x, dict)]
        affected, fixed = [], []
        for x in versions:
            if x.get("status") != "affected":
                continue
            lo, hi = _s(x.get("version"), 64), _s(x.get("lessThan") or x.get("lessThanOrEqual"), 64)
            r = {"text": f"{lo} – < {hi}" if hi else lo}
            if lo and lo not in ("0", "*", "All"):
                r |= {"from": lo, "from_incl": True}
            if hi:
                r |= {"to": hi, "to_incl": bool(x.get("lessThanOrEqual"))}
            if not hi and lo in ("All", "*"):
                r = {"all": True, "text": "alle Versionen"}
            elif not hi and x.get("changes"):
                r = {"from": lo, "from_incl": True, "text": f"ab {lo}"}  # PAN: hotfix branches fix it (see "fixed")
            elif not hi:
                r = {"exact": lo, "text": lo}
            affected.append(r)
            fixed += [_s(c.get("at"), 64) for c in _l(x.get("changes")) if isinstance(c, dict) and c.get("status") == "unaffected"]
            if hi and not x.get("lessThanOrEqual"):
                fixed.append(hi)
        if not affected:
            continue
        plist.append({"vendor": _s(a.get("vendor"), 100), "name": _s(a.get("product"), 150), "cpe": "", "affected": affected[:60], "fixed": sorted(set(fixed), key=_sortkey, reverse=True)[:60], "not_affected": []})
        cna_rows.append({"vendor": _s(a.get("vendor"), 100), "product": _s(a.get("product"), 150), "defaultStatus": _s(a.get("defaultStatus"), 20), "versions": versions[:60]})
    cvss = []
    for m in _l(cna.get("metrics")):
        for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            d = m.get(k) if isinstance(m, dict) else None
            if isinstance(d, dict) and isinstance(d.get("baseScore"), int | float):
                cvss.append({"score": float(d["baseScore"]), "temporal": None, "vector": _s(d.get("vectorString"), 200), "version": _s(d.get("version"), 5)})
                break
    text = lambda key: " ".join(_s(x.get("value"), 600) for x in _l(cna.get(key)) if isinstance(x, dict))[:600]  # noqa: E731
    rems = [{"category": "vendor_fix", "text": text("solutions"), "url": ""}] if text("solutions") else []
    if text("workarounds") and not re.match(r"(?i)^no (known )?workarounds?", text("workarounds")):
        rems.append({"category": "workaround", "text": text("workarounds"), "url": ""})
    exploits = text("exploits")
    ident = _s(meta.get("cveId"), 40)
    return {
        "kind": "paloalto",
        "publisher": PUBLISHER["paloalto"],
        "id": ident,
        "title": _s(cna.get("title"), 300),
        "severity_text": "",
        "summary": text("descriptions"),
        "products": plist[:MAX_PRODUCTS],
        "more_products": 0,
        "cves": [ident] if CVE_ID.fullmatch(ident) else [],
        "cvss": sorted(cvss, key=lambda c: -c["score"])[:1],
        "exploited": bool(exploits) and not re.search(r"(?i)not aware|no (known )?(malicious )?exploit", exploits),
        "remote": any("AV:N" in c["vector"] for c in cvss) or None,
        "mitigation": any(r["category"] == "workaround" for r in rems) or None,
        "remediations": rems,
        "revision": {"current": _s(meta.get("dateUpdated"), 40), "initial": _s(meta.get("datePublished"), 40), "version": "", "summary": "", "count": 0},
        "match": [{"source": "nvd", "data": {"configs": [], "cna": [{"affectedData": cna_rows}], "desc": text("descriptions")}}],
    }


# ---------------------------------------------------------------- Veeam KB (the story's own text)


def veeam_details(adv: dict) -> dict:
    """A Veeam KB article (parsed by vendor_sources.parse_veeam_entry) as details: per product its affected builds per
    release line and the fixed builds, CVSS, CVEs – and the same data for "betrifft deine Systeme" (match)."""
    data = adv["data"]
    products: dict[str, dict] = {}
    cvss, rems = [], []
    for x in data.get("issues") or []:
        for r in x.get("affected") or []:
            e = products.setdefault(r["product"], {"vendor": "Veeam", "name": r["product"][:150], "cpe": "", "affected": [], "fixed": [], "not_affected": []})
            if r.get("earlier"):
                lines = ", ".join(f"{ln}.x" for ln in r.get("lines") or [])
                rng = {"to": r["upto"], "to_incl": True, "text": f"≤ {r['upto']}" + (f" ({lines})" if lines else "")}
            else:
                rng = {"exact": r["upto"], "text": r["upto"]}
            if rng not in e["affected"] and len(e["affected"]) < 30:
                e["affected"].append(rng)
            for ln in x.get("not_lines") or []:
                if f"{ln}.x" not in e["not_affected"]:
                    e["not_affected"].append(f"{ln}.x")
        for r in x.get("fixed") or []:
            e = products.setdefault(r["product"], {"vendor": "Veeam", "name": r["product"][:150], "cpe": "", "affected": [], "fixed": [], "not_affected": []})
            if r["build"] not in e["fixed"]:
                e["fixed"].append(r["build"])
            text = r["product"] + " " + r["name"] + (f" (build {r['build']})" if r["build"] != r["name"] else "")
            if not any(t["text"] == text for t in rems):
                rems.append({"category": "vendor_fix", "text": text[:400], "url": adv["url"]})
        if x.get("cvss") is not None:
            cvss.append({"score": float(x["cvss"]), "temporal": None, "vector": x.get("vector") or "", "version": x.get("cvss_version") or "", "cve": (x.get("cves") or [""])[0]})
    for e in products.values():
        e["fixed"] = sorted(e["fixed"], key=_sortkey, reverse=True)[:60]
    plist = sorted(products.values(), key=lambda p: not p["affected"])
    if not cvss and adv.get("cvss") is not None:
        cvss = [{"score": float(adv["cvss"]), "temporal": None, "vector": "", "version": "", "cve": ""}]
    return {
        "kind": "veeam",
        "publisher": PUBLISHER["veeam"],
        "id": adv["ident"],
        "title": adv["title"],
        "severity_text": "",
        "summary": (adv.get("summary") or "")[:600],
        "products": plist[:MAX_PRODUCTS],
        "more_products": max(0, len(plist) - MAX_PRODUCTS),
        "cves": adv["cves"][:60],
        "cvss": sorted(cvss, key=lambda c: -c["score"])[:1],
        "exploited": False,
        "remote": any("AV:N" in c["vector"] for c in cvss) or None,
        "mitigation": bool(data.get("mitigation")) or None,
        "remediations": rems[:6],
        "revision": {  # the KB dates by day only ("Last Modified: 2026-10-27")
            "current": adv["updated_at"].date().isoformat() if adv.get("updated_at") else "",
            "initial": adv["published_at"].date().isoformat() if adv.get("published_at") else "",
            "version": "",
            "summary": "",
            "count": 0,
        },
        "match": [{"source": "veeam", "data": data}],
    }


# ---------------------------------------------------------------- NVD (fallback), KEV, EUVD


def _nvd_products(a: VendorAdvisory) -> list[dict]:
    """CPE ranges of an NVD record as products: "fortinet:fortios ≥ 7.4.0 < 7.4.9"."""
    out: dict[str, dict] = {}
    for cfg in (a.data or {}).get("configs") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                parts = re.split(r"(?<!\\):", m.get("criteria") or "")
                if len(parts) < 7:
                    continue
                key = ":".join(parts[2:5]).replace("\\", "")
                e = out.setdefault(key, {"vendor": parts[3].replace("_", " ").replace("\\", ""), "name": parts[4].replace("_", " ").replace("\\", ""), "cpe": key, "affected": [], "fixed": [], "not_affected": []})
                if len(e["affected"]) >= 30:
                    continue
                r: dict = {}
                if parts[5] not in ("*", "-", ""):
                    ver = parts[5].replace("\\", "") + ("" if parts[6] in ("*", "-", "") else f" {parts[6]}")
                    r = {"exact": ver, "text": ver}
                else:
                    if m.get("versionStartIncluding") or m.get("versionStartExcluding"):
                        r |= {"from": m.get("versionStartIncluding") or m.get("versionStartExcluding"), "from_incl": bool(m.get("versionStartIncluding"))}
                    if m.get("versionEndExcluding") or m.get("versionEndIncluding"):
                        r |= {"to": m.get("versionEndExcluding") or m.get("versionEndIncluding"), "to_incl": bool(m.get("versionEndIncluding"))}
                        if m.get("versionEndExcluding"):
                            e["fixed"].append(m["versionEndExcluding"])
                    r["text"] = " ".join(x for x in (f"≥ {r['from']}" if r.get("from") and r.get("from_incl") else f"> {r['from']}" if r.get("from") else "", f"≤ {r['to']}" if r.get("to") and r.get("to_incl") else f"< {r['to']}" if r.get("to") else "") if x) or "alle Versionen"
                    if not r.get("from") and not r.get("to"):
                        r = {"all": True, "text": "alle Versionen"}
                e["affected"].append(r)
    for e in out.values():
        e["fixed"] = sorted(set(e["fixed"]), key=_sortkey)
    return list(out.values())[:MAX_PRODUCTS]


def _cve5_products(a: VendorAdvisory) -> list[dict]:
    """The CNA's affected rows of a cvelistV5 record as products: "Example Corp Gateway: 2.0 – < 2.4.1 · fix 2.4.1"."""
    out = []
    for x in (a.data or {}).get("cna") or []:
        for r in x.get("affectedData") or []:
            affected, fixed = [], []
            for v in r.get("versions") or []:
                if v.get("status") != "affected":
                    continue
                lo, hi = str(v.get("version") or ""), str(v.get("lessThan") or v.get("lessThanOrEqual") or "")
                if hi:
                    affected.append({"to": hi, "to_incl": bool(v.get("lessThanOrEqual")), "text": (f"{lo} – " if lo not in ("", "0", "*", "n/a", "unspecified") else "") + ("≤ " if v.get("lessThanOrEqual") else "< ") + hi})
                    if not v.get("lessThanOrEqual"):
                        fixed.append(hi)
                elif lo:
                    affected.append({"exact": lo, "text": lo})
                fixed += [str(c.get("at")) for c in v.get("changes") or [] if c.get("status") == "unaffected" and c.get("at")]
            if not affected and r.get("defaultStatus") == "affected":
                affected = [{"all": True, "text": "alle Versionen"}]
            if affected:
                out.append({"vendor": str(r.get("vendor") or "")[:100], "name": str(r.get("product") or "")[:150], "cpe": "", "affected": affected[:30], "fixed": sorted(set(fixed), key=_sortkey, reverse=True)[:30], "not_affected": []})
    return out[:MAX_PRODUCTS]


def nvd_details(advs: list[VendorAdvisory], cves: list[str], kind: str = "nvd", extra: dict | None = None, cvl: list[VendorAdvisory] | None = None) -> dict:
    """Details from the NVD records of a story's CVEs – and, for those the NVD has not analysed, the cvelistV5 records
    (the CNA's ranges, CISA's CVSS, SSVC and KEV)."""
    cvl = cvl or []
    products: list[dict] = []
    for a in advs:
        for p in _nvd_products(a):
            if not any(p["cpe"] == q["cpe"] for q in products):
                products.append(p)
    for a in cvl:
        for p in _cve5_products(a):
            if not any((p["vendor"], p["name"]) == (q["vendor"], q["name"]) for q in products):
                products.append(p)
    products = products[:MAX_PRODUCTS]
    scores = [{"score": a.cvss, "temporal": None, "vector": "", "version": "", "cve": a.ident} for a in advs if a.cvss is not None]
    scored = {x["cve"] for x in scores}
    scores += [{"score": a.cvss, "temporal": None, "vector": (a.data or {}).get("cvss_vector") or "", "version": "", "cve": a.ident} for a in cvl if a.cvss is not None and a.ident not in scored]
    kev = next(((a.data or {}).get("kev") for a in [*advs, *cvl] if (a.data or {}).get("kev")), None)
    remote = None
    for a in advs:
        status = (a.data or {}).get("desc") or ""
        if re.search(r"(?i)remote|unauthenticated|network", status):
            remote = True
    out = {
        "kind": kind,
        "publisher": PUBLISHER.get(kind, "NVD"),
        "via_nvd": True,
        "id": cves[0] if cves else "",
        "title": advs[0].title if advs else cvl[0].title if cvl else "",
        "severity_text": "",
        "summary": "",
        "products": products,
        "more_products": 0,
        "cves": cves[:60],
        "cvss": sorted(scores, key=lambda c: -c["score"])[:3],
        "exploited": bool(kev) or any(a.exploited for a in [*advs, *cvl]),
        "remote": remote,
        "mitigation": None,
        "remediations": [],
        "revision": {"current": max((a.updated_at.isoformat() for a in [*advs, *cvl] if a.updated_at), default=""), "initial": "", "version": "", "summary": "", "count": 0},
        "match": [{"source": "nvd", "data": a.data or {}} for a in advs] + [{"source": "cvelist", "data": a.data or {}} for a in cvl],
        "via_cvelist": bool(cvl),
        "ssvc": next(((a.data or {}).get("ssvc") for a in cvl if (a.data or {}).get("ssvc")), None),
    }
    if extra:
        out |= extra
    return out


# ---------------------------------------------------------------- fetching


_forti_csaf: dict[str, str] = {}  # FG-IR id → CSAF address (from the PSIRT RSS)
_forti_loaded = [-1e9]  # when the RSS was read (monotonic) – at most every 6 hours, also for advisories not in it


async def _nvd_cve(db: AsyncSession, cve: str, key: str, budget: list[int]) -> VendorAdvisory | None:
    """An NVD record – from what Vendor News stored (if younger than a week), else one request (budget permitting).
    Nothing is written before the request; when it was asked is written after it (also after a failure)."""
    a = await db.get(VendorAdvisory, f"nvd:{cve}")
    if a is not None and a.fetched_at and datetime.now(UTC) - a.fetched_at < NVD_EVERY:
        return a
    st = await db.get(VendorFetch, f"nvdcve:{cve}")
    if st is not None and st.last_fetch_at and datetime.now(UTC) - st.last_fetch_at < NVD_EVERY:
        return a  # asked within the week (also when NVD did not know it yet)
    if budget[0] <= 0:
        return a
    budget[0] -= 1
    asked = datetime.now(UTC)
    ok = False
    try:
        body = await vendor.get(src.nvd_url(cveId=cve), db=db, headers={"apiKey": key} if key else {}, has_key=bool(key), conditional=False, limit=4 * 1024 * 1024)
        ok = True
    finally:
        if st is None:
            st = VendorFetch(key=f"nvdcve:{cve}", failures=0, items=0)
            db.add(st)
        st.last_fetch_at = asked
        if ok:
            st.last_ok_at = datetime.now(UTC)
        await db.commit()
    _, advs = await asyncio.to_thread(src.parse_nvd, body or b'{"vulnerabilities": []}')
    if advs:
        await vendor.store(db, advs, await vendor.current_index(db))
    return await db.get(VendorAdvisory, f"nvd:{cve}", populate_existing=True)


async def _fortinet_csaf(db: AsyncSession, ident: str) -> str | None:
    import time

    if ident not in _forti_csaf and time.monotonic() - _forti_loaded[0] > 6 * 3600:
        _forti_loaded[0] = time.monotonic()
        body = await vendor.get(src.FORTI_RSS, db=db, conditional=False)
        for it in src.parse_forti_rss(body or b"<rss><channel/></rss>"):
            if it["csaf"]:
                _forti_csaf[it["ident"]] = it["csaf"]
    return _forti_csaf.get(ident)


async def _cvelist_for(db: AsyncSession, cves: list[str], advs: list[VendorAdvisory], budget: list[int] | None) -> list[VendorAdvisory]:
    """The cvelistV5 records of the CVEs the NVD cannot describe (no record, or no CPE configuration yet) – within the
    round's budget; a failed lookup only leaves the record out."""
    if not budget:
        return []
    from app import cvelist

    analysed = {a.ident for a in advs if (a.data or {}).get("configs")}
    out = []
    for c in cves:
        if c in analysed:
            continue
        try:
            if (a := await cvelist.single(db, c, budget)) is not None:
                out.append(a)
        except NewsError as exc:
            log.info("details: cvelistV5 %s: %s", c, exc.category)
            if exc.category == "rate_limited":
                budget[0] = 0
    return out


async def build(db: AsyncSession, item: NewsItem, source: NewsSource, prev: dict | None, key: str, budget: list[int], cvl_budget: list[int] | None = None) -> dict | None:
    """The details of one story (None: nothing structured to show; `prev`: what it had so far). Raises NewsError on a
    failed request. Writes only what it fetched (advisories, request state), each in a short transaction after its
    request – the story's own row is the caller's."""
    cves = [c.upper() for c in item.cves or []]
    kind, ident, url = plan(source.key, item.url, cves)
    if kind in ("bsi", "siemens", "cisco", "fortinet"):
        if kind == "fortinet":
            url = await _fortinet_csaf(db, ident)
            if not url:
                kind = "nvd" if cves else "none"
        if url:
            body = await vendor.get(url, db=db, conditional=False, limit=CSAF_LIMIT)
            # all products for Vendor News (the same advisory from its CSAF provider is stored alike), the first ones shown
            d = await asyncio.to_thread(parse_csaf, body or b"{}", kind, STORE_PRODUCTS)
            if not d["cvss"] and d["cves"]:
                advs = [a for c in d["cves"][:MAX_CVES] if (a := await _nvd_cve(db, c, key, budget))]
                if advs:
                    d["cvss"] = sorted([{"score": a.cvss, "temporal": None, "vector": "", "version": "", "cve": a.ident, "nvd": True} for a in advs if a.cvss is not None], key=lambda c: -c["score"])[:1]
                    d["exploited"] = d["exploited"] or any(a.exploited for a in advs)
            if kind != "fortinet":  # Fortinet's advisories come into Vendor News from its own source already
                await _store_as_advisory(db, d, item)
            return shown(d)
    if kind == "paloalto":
        body = await vendor.get(url, db=db, conditional=False, limit=CSAF_LIMIT)
        return await asyncio.to_thread(parse_cve5, body or b"{}")
    if kind == "veeam":
        adv = await asyncio.to_thread(src.parse_veeam_entry, item.title, item.url, item.content_html or "", item.published_at)
        return veeam_details(adv) if adv is not None else None  # None: a running list of fixes, no advisory
    if kind in ("kev", "euvd", "nvd"):
        advs = [a for c in cves[:MAX_CVES] if (a := await _nvd_cve(db, c, key, budget))]
        cvl = await _cvelist_for(db, cves[:MAX_CVES], advs, cvl_budget)
        extra: dict = {}
        if kind == "kev":
            k = await db.get(VendorKev, cves[0])
            extra = {"exploited": True, "kev": {"added": k.date_added, "due": k.due, "ransomware": k.ransomware} if k else _kev_from_story(item)}
        if kind == "euvd":
            extra = {"exploited": True}
            if not advs:
                score = next((float(r["value"]) for r in item.reasons or [] if r.get("kind") == "cvss" and re.fullmatch(r"\d+(\.\d)?", str(r.get("value")))), None)
                if score is not None:
                    extra["cvss"] = [{"score": score, "temporal": None, "vector": "", "version": "", "cve": cves[0]}]
        if not advs and not cvl and not extra:
            return None if budget[0] > 0 else prev  # no NVD record (yet) – or no budget left this round
        return nvd_details(advs, cves, kind, extra, cvl)
    return None


def _kev_from_story(item: NewsItem) -> dict | None:
    due = next((r.get("value") for r in item.reasons or [] if r.get("kind") == "kev"), "")
    return {"added": "", "due": due or "", "ransomware": any(r.get("kind") == "ransomware" for r in item.reasons or [])}


def shown(d: dict) -> dict:
    """Details as the story shows them: the first MAX_PRODUCTS products."""
    if len(d["products"]) <= MAX_PRODUCTS:
        return d
    return {**d, "products": d["products"][:MAX_PRODUCTS], "more_products": d.get("more_products", 0) + len(d["products"]) - MAX_PRODUCTS}


def csaf_advisory(d: dict, url: str, *, title: str = "", summary: str = "", published=None) -> dict | None:  # noqa: ANN001
    """A parsed CSAF document as a Vendor News advisory (`csaf:<tracking id>` – one record per document, however it
    came: a story of the BSI, Siemens or Cisco, or the provider's own feed); None without an affected product."""
    if not d.get("id") or not any(p["affected"] for p in d["products"]):
        return None
    pub = _date(d["revision"].get("initial") or "") or published
    upd = _date(d["revision"].get("current") or "") or pub
    score = d["cvss"][0]["score"] if d["cvss"] else None
    return {
        "id": f"csaf:{d['id']}"[:120],
        "source": "csaf",
        "ident": d["id"][:100],
        "title": d["title"] or title,
        "summary": d["summary"] or summary,
        "url": url,
        "cves": d["cves"][:30],
        "cvss": score,
        "severity": src.severity_of(score, {"kritisch": "critical", "hoch": "high", "mittel": "medium", "niedrig": "low"}.get(d["severity_text"].lower(), d["severity_text"])),
        "exploited": d["exploited"],
        "published_at": pub,
        "updated_at": upd,
        "names": [p["name"] for p in d["products"]],
        "data": {
            "products": d["products"],
            "publisher": d["publisher"],
            "rev": d["revision"].get("version") or "",  # the document's own version (advisory_changes: shown, no change by itself)
            # Siemens / Cisco speak only for their own products – also when their advisory comes with a story
            # (vendor_match.csaf_speaks_for; the CSAF provider of the same vendor stores the same record)
            **({"provider": d["kind"]} if d.get("kind") in PROVIDER_KINDS else {}),
        },
    }


def advisory_ids(kind: str, ident: str, cves: list[str]) -> list[str]:
    """The Vendor News records behind a story's details (their revisions are shown with it): the CSAF document, the
    vendor's advisory – and for a story of the NVD, the KEV or the EUVD the NVD records of its first CVEs."""
    out: list[str] = []
    if kind in ("bsi", "siemens", "cisco") and ident:
        out.append(f"csaf:{ident}")
    elif kind in ("paloalto", "fortinet", "veeam") and ident:
        out.append(f"{kind}:{ident}")
    if kind in ("nvd", "kev", "euvd"):
        out += [f"nvd:{c.upper()}" for c in cves[:MAX_CVES]]
    return out


async def _store_as_advisory(db: AsyncSession, d: dict, item: NewsItem) -> None:
    """A CSAF advisory (BSI, Siemens, Cisco) as a Vendor News advisory: followed products get a finding from it. A
    Siemens or Cisco document only under a tracking id of its own kind (the record its CSAF provider shares)."""
    from app.csaf_providers import TRACKING

    if (pattern := TRACKING.get(d.get("kind") or "")) is not None and not pattern.match(d.get("id") or ""):
        log.info("details: %s document with a foreign tracking id %r not stored", d.get("kind"), str(d.get("id"))[:60])
        return
    adv = csaf_advisory(d, item.url, title=item.title, summary=html_to_text(item.summary or ""), published=item.published_at)
    if adv is not None:
        await vendor.store(db, [adv], await vendor.current_index(db))


async def enrich_round(db: AsyncSession, *, limit: int = 60) -> int:
    """Stories without details (or due again), newest first – within the round's budget. Never a write transaction
    across a request: a story's row is written after its details were fetched, in a short transaction of its own."""
    from app import news as news_svc

    cfg = await news_svc.config(db)
    if not cfg.get("enabled") or not cfg.get("details", True):
        return 0
    vcfg = await vendor.config(db)
    key = vendor.nvd_key(vcfg)
    budget = [NVD_PER_ROUND[1] if key else NVD_PER_ROUND[0]]
    # cvelistV5 for the CVEs the NVD has not analysed – while Vendor News and the source are switched on
    cvl_budget = [CVELIST_PER_ROUND if vcfg.get("enabled", True) and vcfg.get("cvelist", True) else 0]
    csaf_left = CSAF_PER_ROUND
    now = datetime.now(UTC)
    done = 0
    fol: list | None = None  # the followed products – read once, when the first details arrive (story.products)
    # only the stories without details or due again, among the newest 2000 – by the index, a few columns: not every
    # stored detail with its JSON every minute (20k stories: half a second on the event loop, every round)
    floor = await db.scalar(
        select(NewsItem.published_at).join(NewsSource, NewsSource.id == NewsItem.source_id).where(news_svc.visible()).order_by(NewsItem.published_at.desc()).offset(1999).limit(1)
    )
    stmt = (
        select(NewsItem.id, NewsSource.id)
        .join(NewsSource, NewsSource.id == NewsItem.source_id)
        .outerjoin(StoryDetail, StoryDetail.item_id == NewsItem.id)
        .where(news_svc.visible(), or_(StoryDetail.item_id.is_(None), and_(StoryDetail.next_try_at.is_not(None), StoryDetail.next_try_at <= now)))
        .order_by(NewsItem.published_at.desc())
        .limit(2000)
    )
    if floor is not None:
        stmt = stmt.where(NewsItem.published_at >= floor)
    for item_id, source_id in (await db.execute(stmt)).all():
        item, source = await db.get(NewsItem, item_id), await db.get(NewsSource, source_id)
        if item is None or source is None:
            continue
        det = await db.get(StoryDetail, item_id)
        kind, ident, _ = plan(source.key, item.url, [c.upper() for c in item.cves or []])
        if kind == "none":
            if det is None:
                db.add(StoryDetail(item_id=item.id, kind="none", status="none", fetched_at=now))
            continue
        if kind in DOCUMENT_KINDS:
            if csaf_left <= 0:
                continue
            csaf_left -= 1
        elif kind == "veeam":
            pass  # read from the story's own text – no request
        elif budget[0] <= 0:
            continue
        await dbm.release(db)  # the "none" rows so far – nothing pending while build() waits on the network
        try:
            d = await build(db, item, source, det.data if det else None, key, budget, cvl_budget)
            err: NewsError | Exception | None = None
        except NewsError as exc:
            d, err = None, exc
        except SQLAlchemyError:
            await db.rollback()
            log.exception("details round stopped: database error")
            break  # the next round goes on
        except Exception as exc:  # noqa: BLE001 - one story never stops the round
            log.exception("details for %s failed", item.id)
            d, err = None, exc
        if det is None:
            det = StoryDetail(item_id=item.id, kind=kind, status="pending", failures=0)
            db.add(det)
        det.kind, det.ident = kind, ident[:120]
        if err is None:
            det.data, det.status, det.error, det.failures, det.fetched_at = d, "ok" if d else "none", None, 0, now
            young = now - item.published_at < FRESH
            again = CSAF_EVERY if kind in (*DOCUMENT_KINDS, "veeam") else NVD_EVERY  # Veeam: the KB text may have changed with the story
            det.next_try_at = (now + again) if (d and young) or (not d and kind in ("nvd", "kev", "euvd") and young) else None
        elif isinstance(err, NewsError):
            det.failures = (det.failures or 0) + 1
            det.status, det.error = ("ok" if det.data else "error"), (f"{err.category}: {err.detail}" if err.detail else err.category)[:200]
            det.next_try_at = now + min(timedelta(hours=1) * (2 ** min(det.failures, 5)), timedelta(hours=24))
            if err.category == "http" and "404" in (err.detail or "") and not det.data:
                det.status, det.next_try_at = "none", None  # no public document (e.g. TLP:GREEN at the BSI) – not asked again
            if err.category == "rate_limited":
                budget[0] = 0
        else:
            det.failures, det.status, det.next_try_at = (det.failures or 0) + 1, "error", now + timedelta(hours=6)
        await db.commit()
        if err is None:
            # the details may make it "exploited" or "ohne Patch" (CSAF: no fix available) – its topics again; and the
            # followed products they concern ("Betrifft unsere Produkte")
            await news_svc.retopic(db, NewsItem.id == item.id)
            if fol is None:
                fol = await followed(db)
            await set_products(db, item.id, products_of(d, fol))
            await db.commit()
        done += 1
        if done >= limit:
            break
    await db.commit()
    return done


# ---------------------------------------------------------------- the story and the followed products


async def followed(db: AsyncSession) -> list[tuple[dict, list[VendorVersion]]]:
    fs = list(await db.scalars(select(VendorFollow).where(VendorFollow.enabled.is_(True))))
    vers = await vendor.versions_of(db, [f.id for f in fs])
    return [(p, vers.get(f.id, [])) for f in fs if (p := vendor.product_of(f))]


def matches(details: dict | None, fol: list[tuple[dict, list[VendorVersion]]]) -> list[dict]:
    """Which followed products (and versions) a story's details concern – "betrifft deine Systeme"."""
    if not details:
        return []
    out = []
    for p, vers in fol:
        rows = []
        for v in vers or [None]:
            text = v.version if v else None
            verdict = None
            if details.get("kind") in ("bsi", "siemens", "cisco", "fortinet"):
                # through evaluate() as Vendor News judges the same document: a short version ("7.4") stands for every
                # release inside it, an unparsed one is "possible"
                verdict = evaluate(p, "csaf", details, text)
            for m in details.get("match") or []:
                verdict = worst(verdict, evaluate(p, m["source"], m["data"], text))
            if verdict is None:
                continue
            rows.append({"id": str(v.id) if v else None, "version": text, "label": v.label if v else "", "status": verdict.status, "fixed": verdict.fixed, "reason": verdict.reason})
        if rows and any(r["status"] != "not_affected" for r in rows):
            out.append({"product": p["key"], "label": p.get("label"), "versions": rows})
    return out


def hint(details: dict | None) -> dict | None:
    """What a card shows: the CVSS and the first affected product with its range."""
    if not details:
        return None
    first = next((p for p in details.get("products") or [] if p.get("affected")), None)
    rng = ", ".join(r.get("text") or "" for r in (first or {}).get("affected", [])[:2]) if first else ""
    return {
        "cvss": details["cvss"][0]["score"] if details.get("cvss") else None,
        "product": f"{first['name']} {rng}".strip()[:120] if first else None,
        "exploited": bool(details.get("exploited")),
    }


# ---------------------------------------------------------------- the story's products ("Betrifft unsere Produkte")
#
# news_items.products: the followed products a story's details concern – exactly matches() (the drawer's "Betrifft deine
# Systeme"): the advisory's structured data (CSAF product tree, the NVD's CPE configurations, the CNA's affected rows)
# judged by Vendor News' matcher – a product whose every entered version is "not affected" does not count, a product
# without versions does. Never the words of the story (a keyword "Exchange" in a headline is no product hint).
# Computed when the details arrive (enrich_round), for every stored story once per PRODUCTS_V, and again for the
# products whose follow or versions changed (products_round: a signature per product, kept in the settings row
# PRODUCTS_STATE – a product no longer followed is taken out of every list without looking at the details).

PRODUCTS_V = 1
PRODUCTS_STATE = "news_products"
PRODUCTS_BATCH = 500
_products_gen = [-1]  # vendor.gen.value at the last look – unchanged: nothing followed changed, no signature computed


def products_of(details: dict | None, fol: list[tuple[dict, list[VendorVersion]]]) -> list[str]:
    """The followed products (catalogue keys, sorted) these details concern."""
    return sorted({m["product"] for m in matches(details, fol)}) if details and fol else []


async def set_products(db: AsyncSession, item_id, keys: list[str]) -> None:  # noqa: ANN001
    await db.execute(update(NewsItem).where(NewsItem.id == item_id, NewsItem.products != cast(literal(json.dumps(keys)), JSONB)).values(products=keys))


def _signature(fol: list[tuple[dict, list[VendorVersion]]]) -> dict[str, str]:
    """Per followed product: a hash of what decides its matches – the catalogue's entry (names, CPEs, scheme) and the
    entered versions."""
    out = {}
    for p, vers in fol:
        blob = json.dumps([p, sorted(str(v.version or "") for v in vers or [])], sort_keys=True, default=str)
        out[str(p["key"])] = hashlib.sha256(blob.encode()).hexdigest()[:20]
    return out


async def followed_labels(db: AsyncSession) -> dict[str, str]:
    """The followed products by key with their label ("PAN-OS") – the cards' badge "Unser Produkt: …"."""
    out = {}
    for f in await db.scalars(select(VendorFollow).where(VendorFollow.enabled.is_(True))):
        if p := vendor.product_of(f):
            out[str(p["key"])] = str(p.get("label") or p.get("name") or p["key"])
    return out


async def reproduct(db: AsyncSession, fol: list[tuple[dict, list[VendorVersion]]], keys: set[str] | None = None) -> int:
    """The stored stories' products computed again – for these product keys only (the rest of each list stays), or all of
    them (None: every list replaced). Keys no longer followed leave every list by SQL alone; the others are judged
    against the stored details in chunks of PRODUCTS_BATCH stories (off the event loop), each chunk committed on its
    own. Returns how many stories changed."""
    have = {str(p["key"]) for p, _ in fol}
    changed = 0
    if keys is not None:
        if gone := sorted(keys - have):
            res = await db.execute(
                update(NewsItem)
                .where(NewsItem.products.op("?|")(pg_array(gone)))
                .values(products=NewsItem.products.op("-")(cast(pg_array(gone), ARRAY(Text))))
                .execution_options(synchronize_session=False)
            )
            changed += res.rowcount or 0
            await db.commit()
        fol = [x for x in fol if str(x[0]["key"]) in keys]
        if not fol:
            return changed
    else:
        # every list replaced: a story without (usable) details concerns no product – nothing followed: none does
        empty = NewsItem.products != cast(literal("[]"), JSONB)
        has = select(StoryDetail.item_id).where(StoryDetail.item_id == NewsItem.id, StoryDetail.status == "ok", StoryDetail.data.is_not(None)).exists()
        res = await db.execute(update(NewsItem).where(empty, ~has if fol else true()).values(products=[]).execution_options(synchronize_session=False))
        changed += res.rowcount or 0
        await db.commit()
        if not fol:
            return changed
    last = None
    while True:
        stmt = (
            select(StoryDetail.item_id, cast(StoryDetail.data, Text), NewsItem.products)
            .join(NewsItem, NewsItem.id == StoryDetail.item_id)
            .where(StoryDetail.status == "ok", StoryDetail.data.is_not(None))
            .order_by(StoryDetail.item_id)
            .limit(PRODUCTS_BATCH)
        )
        if last is not None:
            stmt = stmt.where(StoryDetail.item_id > last)
        rows = (await db.execute(stmt)).all()
        if not rows:
            break
        last = rows[-1][0]

        def compute(rows=rows) -> list[dict]:  # noqa: ANN001
            out = []
            for iid, raw, old in rows:
                hit = products_of(json.loads(raw) if raw else None, fol)
                new = hit if keys is None else sorted({k for k in old or [] if k not in keys} | set(hit))
                if new != list(old or []):
                    out.append({"id": iid, "products": new})
            return out

        upd = await asyncio.to_thread(compute)
        await dbm.release(db)
        if upd:
            await db.execute(update(NewsItem), upd)
            changed += len(upd)
        await db.commit()
        if len(rows) < PRODUCTS_BATCH:
            break
    return changed


async def products_round(db: AsyncSession) -> int | None:
    """Background (after the details round): the stories' products once per PRODUCTS_V (a new installation, the upgrade
    that brought the column – every list), else again for the products whose follow or versions changed since the last look (their
    signature) – a follow added, switched off, removed, a version entered. Nothing changed: None (and while Vendor
    News' generation counter stands still not even the signatures are computed)."""
    stamp = vendor.gen.value
    state = await settings_store.get(db, PRODUCTS_STATE)
    due = int(state.get("v") or 0) < PRODUCTS_V
    if not due and _products_gen[0] == stamp:
        return None
    fol = await followed(db)
    sig = _signature(fol)
    old = state.get("sig") if isinstance(state.get("sig"), dict) else {}
    keys = None if due else {k for k in set(sig) | set(old) if sig.get(k) != old.get(k)}
    n = None
    if keys is None or keys:
        await dbm.release(db)
        n = await reproduct(db, fol, keys)
        await settings_store.put(db, PRODUCTS_STATE, {"v": PRODUCTS_V, "sig": sig})
        await db.commit()
        if n:
            log.info("details: products of %d stories computed", n)
    _products_gen[0] = stamp
    return n


def reset_products() -> None:
    """Forget the last look (tests: a database of their own each)."""
    _products_gen[0] = -1
