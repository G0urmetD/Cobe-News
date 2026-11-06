"""Is this installed version affected? One verdict per advisory, product and version – pure functions, no I/O (the
product's version rules and release lines come from the catalogue in memory, app/version_input.py).

Verdicts:
- ``affected``      the version is in an affected range or listed as affected
- ``possible``      "möglicherweise betroffen – Version nicht eindeutig": the data does not decide (a version string we
                    cannot compare, a range less precise than the version, a release line the advisory does not name …)
- ``not_affected``  only when the data decides it: the version is at or above the fix, its line is listed as not
                    affected, or it is newer than every version the advisory names for its line
- ``service``       a cloud service of the vendor (no version on the customer side) is named – the vendor fixes it
- ``unversioned``   the product is followed without a version: the advisory concerns the product
- ``stale``         set by vendor.findings, not here: "unklare Altdaten" – a "possible" whose data is unclear and that
                    was published long before the installed release line existed (not counted, not notified)

Sources: Palo Alto's advisory JSON (per product line "< 11.2.4-h22, < 11.2.7-h21, …" and an explicit list of affected
versions), Fortinet's CSAF ("FortiOS >=7.6.1|<=7.6.6", "FortiOS 7.4 all versions"), the NVD's CVE records (CPE
configurations with version ranges, and the CNA's affected data – Microsoft writes build ranges there), Veeam's
security KB articles (per CVE "13.1.1.18 and all earlier version 13.1 builds", fixed in "13.1.2 (build 13.1.2.57)"),
CSAF 2.0 documents (BSI, Siemens, Cisco …: ranges per product), the CVE records of cvelistV5 (the CNA's affected data,
else CISA's ADP enrichment with CPE names) and OSV records (ECOSYSTEM/SEMVER ranges of the product's packages).
"""

import functools
import re
from dataclasses import dataclass, field

from app import version_input
from app.vendor_versions import VEEAM_BUILD_DEPTH, V, from_cpe, ios_classic, parse, windows_cpe

ORDER = {"affected": 5, "possible": 4, "service": 3, "unversioned": 2, "stale": 1, "not_affected": 0}


@dataclass
class Verdict:
    status: str
    reason: str
    fixed: str | None = None
    detail: dict = field(default_factory=dict)


def worst(a: Verdict | None, b: Verdict | None) -> Verdict | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if ORDER[a.status] >= ORDER[b.status] else b


# Where a verdict comes from – Verdict.detail["by"]; the drawer says "laut Hersteller" only for the vendor's own word:
#   vendor  the vendor's advisory (Palo Alto, Fortinet, Veeam), a CSAF provider's own document, the CNA's affected
#           rows of a CVE record (they name the product's vendor – eval_cna matches no other)
#   nvd     the NVD's own analysis (CPE configurations)
#   adp     CISA's ADP enrichment of a CVE record
#   bsi     a CSAF document of the BSI (CERT-Bund) – a third party that sums up the vendors' data
#   csaf    a CSAF document of another publisher that is not a provider of csaf.yaml
#   osv     an OSV record (the ecosystem's advisory database)
BY_VENDOR = "vendor"
THIRD_PARTY = frozenset({"bsi", "csaf"})


def _from(v: Verdict | None, by: str | None) -> Verdict | None:
    """The verdict with its origin – one that already has one keeps it (a combination takes the deciding side's)."""
    if v is not None and by and "by" not in v.detail:
        v.detail = {**v.detail, "by": by}
    return v


def _like(base: Verdict | None, status: str, reason: str, fixed: str | None = None) -> Verdict:
    """A verdict derived from another one (a version we cannot compare, a short version …): the same origin."""
    by = base.detail.get("by") if base is not None else None
    return Verdict(status, reason, fixed, {"by": by} if by else {})


# ---------------------------------------------------------------- helpers


_NON_WORD = re.compile(r"[^a-z0-9.]+")


@functools.lru_cache(maxsize=8192)
def _norm(s: str) -> tuple[str, ...]:
    """The words of a name, lower case ("&" is "and") – cached: the same few hundred product and vendor names are
    compared for every record of a product (a third of the evaluation's time before)."""
    return tuple(_NON_WORD.sub(" ", (s or "").lower().replace("&", " and ")).split())


def name_words(s: str) -> list[str]:
    """The words name_matches compares (vendor.relink preselects by them)."""
    return list(_norm(s))


def name_matches(name: str, wanted: str, vendor: str = "") -> bool:
    """A product name in an advisory or CNA record is the wanted one: the same words, maybe after the vendor's name and
    followed by a version or edition number ("Microsoft Exchange Server 2019 Cumulative Update 14" is "Exchange Server";
    "phpMyAdmin" is not "PHP")."""
    got, want = _norm(name), _norm(wanted)
    if not want:
        return False
    for v in _norm(vendor):
        if got[:1] == (v,) and want[:1] != (v,):
            got = got[1:]
    if got[: len(want)] != want:
        return False
    rest = got[len(want) :]
    return not rest or bool(re.match(r"^\d", rest[0])) or rest[0] in ("cumulative", "update", "for", "sp", "cu", "lts", "x64", "server", "(chromium-based)", "chromium")


def _line_of(v: V, n: int = 2) -> tuple[int, ...]:
    return v.key[:n]


VTEXT_MAX = 1000  # a version expression of an advisory is short – a longer one is cut (the regexes below are quadratic on it)


def _vkey_text(text: str) -> str:
    return re.sub(r"\s*\([^)]*\)\s*", " ", text[:VTEXT_MAX].replace("*", "")).strip()


_ALT = re.compile(r"^(.*?\S)\s*\(([^()]*)\)\s*$")
_PLAIN = re.compile(r"^v?\d+(?:\.\d+)+$")


def bound_v(scheme: str, text) -> V | None:
    """A version bound as advisories write it: "21.0 MR1 (21.0.1)" – two ways of saying one version, the plain one in
    brackets counts (read as a whole it was 21.0.1.21.0.1); "7.2.5 (build 208)" or "6.2.8-h2 (6.2.8-c243)" – the
    version in front counts. Else the scheme, then the generic rule."""
    if not isinstance(text, str):
        return None
    t = text.strip()
    if m := _ALT.match(t):
        outer, inner = m.group(1), m.group(2).strip()
        iv = (parse(scheme, inner) or parse("generic", inner)) if _PLAIN.match(inner) else None
        ov = parse(scheme, outer) or parse("generic", outer)
        if iv is not None and (ov is None or ov.key[:1] == iv.key[:1]):
            return iv
        if ov is not None:
            return ov
    return parse(scheme, t) or parse("generic", t)


def upto(v: V, end: V, incl: bool, line: bool = False) -> bool:
    """v is below an upper bound: < end, or = end when it is inclusive. An inclusive bound with fewer parts than v
    stands for its whole line – "21.0.0 and older" (≤ 21.0.0) includes 21.0.0.169, Mozilla's "≤ 128.*" every 128.x
    (as Veeam's "13.1.1.18 and all earlier version 13.1 builds"). `line`: the bound was written "2.426.*"."""
    if v < end:
        return True
    if (incl or line) and v == end:
        return incl
    return (incl or line) and end.depth < v.depth and v.startswith(end)


def _same_line(v: V, at: V) -> bool:
    """A change at 1.26.3 is about the line 1.26 (all parts but the last); R32 P1 about R32."""
    return len(at.key) > 1 and (v.key + (0,) * len(at.key))[: len(at.key) - 1] == at.key[:-1]


def edition_of(product: dict, name: str) -> dict | None:
    """The catalogue edition a CNA product name speaks of ("Microsoft SharePoint Server 2019" → 2019): all words of
    the edition's name in it, the most specific one."""
    words = set(_norm(name))
    hits = [e for e in product.get("editions") or [] if set(_norm(e["name"])) <= words]
    return max(hits, key=lambda e: len(_norm(e["name"])), default=None)


def in_edition(scheme: str, e: dict, v: V) -> bool:
    start = parse(scheme, e["from"]) or parse("generic", e["from"])
    below = (parse(scheme, e["below"]) or parse("generic", e["below"])) if e.get("below") else None
    return (start is None or v >= start) and (below is None or v < below)


def _edition_by_cpe(product: dict, token: str) -> dict | None:
    t = (token or "").replace("\\", "").lower()
    return next((e for e in product.get("editions") or [] if e.get("cpe") and e["cpe"].lower() == t), None) if t not in ("", "*", "-") else None


_FLAVOUR = re.compile(r"(?i)(?<![a-z])(fips|ndcpp)(?![a-z])")


# ---------------------------------------------------------------- Palo Alto


_PAN_BOUND = re.compile(r"^(<=|>=|<|>|=)?\s*([0-9][0-9A-Za-z.\-]*)(?:\s+on\s+(.+))?$")


def _pan_bounds(text: str) -> tuple[list[tuple[str, V, str]], list[str], bool]:
    """'< 11.2.4-h22 on Panorama, >= 11.1.2-h9' → [(op, version, platform)], unparsed parts, all/none."""
    out, bad = [], []
    for part in (text or "").split(","):
        p = _vkey_text(part)
        if not p:
            continue
        m = _PAN_BOUND.match(p)
        v = parse("panos", m.group(2)) or parse("generic", m.group(2)) if m else None
        if not m or v is None:
            bad.append(p)
            continue
        out.append((m.group(1) or "=", v, (m.group(3) or "").strip()))
    return out, bad, False


def _pan_line(entry_name: str, names: list[str]) -> tuple[str, V | None] | None:
    """'PAN-OS 11.2' → ('PAN-OS', 11.2); 'GlobalProtect App 6.2' → ('GlobalProtect App', 6.2); 'Prisma Access' → (…, None)."""
    entry = re.sub(r"\s+", " ", entry_name.strip())
    for n in sorted(names, key=len, reverse=True):
        if entry.lower() == n.lower():
            return n, None
        if entry.lower().startswith(n.lower() + " "):
            rest = entry[len(n) + 1 :].strip()
            return n, parse("generic", rest)
    return None


def eval_paloalto(product: dict, data: dict, v: V | None) -> Verdict | None:
    names: list[str] = list(product.get("names") or [])
    if not names:
        return None
    lines = [x for x in data.get("lines") or [] if isinstance(x, dict)]
    is_panorama = product.get("key") == "panorama"
    own = []
    for x in lines:
        hit = _pan_line(str(x.get("name") or ""), names)
        if hit:
            own.append((hit[0], hit[1], str(x.get("affected") or ""), str(x.get("fixed") or "")))
    if not own:
        return None
    derived = False
    if is_panorama:
        pano = [o for o in own if o[0].lower() == "panorama"]
        if pano:
            own = pano
        else:
            own = [o for o in own if o[0].lower() == "pan-os"]
            # a PAN-OS advisory that never says "on Panorama": whether Panorama is affected stands in its text
            derived = not any("panorama" in (o[2] + o[3]).lower() for o in own)
    elif product.get("key") == "panos":
        # "< 11.2.4-h22 on Panorama": Panorama only – not the firewalls (its affected list names PAN-OS versions too)
        bounds_all = [b for _, _, a, _ in own for b in a.split(",") if b.strip() and b.strip().lower() not in ("none", "all")]
        if bounds_all and all("on panorama" in b.lower() for b in bounds_all):
            return Verdict("not_affected", "panorama_only") if v is not None else None
        own = [(n, ln, ",".join(b for b in a.split(",") if "on panorama" not in b.lower()) or "None", f) for n, ln, a, f in own if n.lower() == "pan-os"] or own
    any_affected = any(a.strip().lower() not in ("none", "") for _, _, a, _ in own)
    if product.get("cloud") or product.get("scheme") == "cloud":
        if not any_affected:
            return Verdict("not_affected", "line_none")
        return Verdict("service", "cloud", detail={"lines": [{"line": n + (f" {ln.text}" if ln else ""), "affected": a, "fixed": f} for n, ln, a, f in own]})
    if v is None:
        return Verdict("unversioned", "unversioned") if any_affected else None
    listed = {str(x).strip() for x in data.get("affected_list") or []}
    in_list = any(f"{n} {v.text}" in listed for n in names)
    # the entry for the installed line ("PAN-OS 11.2"), else one for all lines ("PAN-OS")
    line_entries = [o for o in own if o[1] is not None and v.startswith(o[1])]
    entry = max(line_entries, key=lambda o: o[1].depth) if line_entries else next((o for o in own if o[1] is None), None)
    if entry is None:
        if in_list:
            return Verdict("affected", "in_list")
        named = [o[1] for o in own if o[1] is not None]
        if named and all(v > ln and not v.startswith(ln) for ln in named):
            return Verdict("not_affected", "newer_line")
        return Verdict("possible", "line_not_listed")
    _, _, affected, fixed = entry
    verdict = _pan_affected(v, affected, fixed)
    if in_list and verdict.status != "affected":
        verdict = Verdict("affected", "in_list", verdict.fixed)
    if derived and verdict.status == "affected":
        verdict = Verdict("possible", "panorama_derived", verdict.fixed)
    return verdict


def _pan_affected(v: V, affected: str, fixed: str) -> Verdict:
    a = affected.strip()
    low = _vkey_text(a).lower()
    if low in ("none", "") or low.startswith("none on"):
        return Verdict("not_affected", "line_none")
    if low == "all" or low.startswith("all on"):
        return Verdict("affected", "line_all", None, {"platform": a[3:].strip()} if low.startswith("all on") else {})
    bounds, bad, _ = _pan_bounds(a)
    if bad and not bounds:
        return Verdict("possible", "unparsed_data")
    platforms = sorted({p for _, _, p in bounds if p})
    base = v.key[:3]
    same = [(op, b) for op, b, _ in bounds if b.key[:3] == base]
    uppers_same = [(op, b) for op, b in same if op in ("<", "<=")]
    lowers_same = [(op, b) for op, b in same if op in (">=", ">")]
    fixes = _fix_candidates(v, bounds, fixed)
    detail = {"platform": ", ".join(platforms)} if platforms else {}
    if uppers_same or lowers_same:
        above_lower = all(v > b or (op == ">=" and v == b) for op, b in lowers_same) if lowers_same else True
        below_upper = any(v < b or (op == "<=" and v == b) for op, b in uppers_same) if uppers_same else True
        if above_lower and below_upper:
            return Verdict("affected", "in_range", fixes, detail)
        return Verdict("not_affected", "fixed" if uppers_same and not below_upper else "out_of_range", None, detail)
    if bounds and all(op == "=" for op, _, _ in bounds):
        # "affected: 11.2.2, fixed: >= 11.2.3" – single releases; at or above the fix of the line is fixed
        if any(v == b for _, b, _ in bounds):
            return Verdict("affected", "in_list", fixes, detail)
        lows = [b for op, b, _ in _pan_bounds(fixed)[0] if op in (">=", ">")]
        own_line = [b for b in lows if b.key[:2] == v.key[:2]]
        if own_line and v >= min(own_line):
            return Verdict("not_affected", "fixed", None, detail)
        return Verdict("possible", "not_listed", fixes, detail)
    if any(op in (">=", ">") for op, _, _ in bounds):
        return Verdict("possible", "base_not_listed", fixes, detail)  # ranges that start somewhere: an unlisted base is unknown
    uppers = [b for op, b, _ in bounds if op in ("<", "<=")]
    if not uppers:
        return Verdict("possible", "unparsed_data")
    top = max(uppers)
    if v < top:
        return Verdict("affected", "in_range", fixes, detail)
    return Verdict("not_affected", "fixed", None, detail)


def _fix_candidates(v: V, bounds: list[tuple[str, V, str]], fixed: str) -> str | None:
    """The version to go to: the smallest fixed version on the same base (11.2.4-h22 for 11.2.4-h5), else the
    smallest fixed version above the installed one in its line."""
    cands = [b for op, b, _ in bounds if op == "<" and b > v]
    for part in (fixed or "").split(","):
        m = re.match(r"^>=\s*([0-9][0-9A-Za-z.\-]*)", _vkey_text(part))
        if m and (b := parse("panos", m.group(1)) or parse("generic", m.group(1))) and b > v:
            cands.append(b)
    if not cands:
        return None
    same = [b for b in cands if b.key[:3] == v.key[:3]]
    pick = min(same) if same else min((b for b in cands if b.key[:2] == v.key[:2]), default=min(cands))
    return pick.text


# ---------------------------------------------------------------- Fortinet (CSAF)


_FORTI_RANGE = re.compile(r"(>=|<=|>|<|=)?\s*([0-9][0-9.]*)")


def _forti_expr(expr: str, name: str) -> tuple[str, object] | None:
    """'FortiOS >=7.6.1|<=7.6.6' → ('range', [(op, V)]); 'FortiOS/ 7.4 all versions' → ('line', V);
    'FortiOS-7.6.7' → ('exact', V); 'FortiOS all versions' → ('all', None)."""
    e = expr.strip()
    if not e.lower().startswith(name.lower()):
        return None
    rest = e[len(name) :].strip(" /-")
    if re.fullmatch(r"(?i)all\s+versions?", rest):
        return "all", None
    m = re.fullmatch(r"(?i)([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s+all\s+versions?", rest)
    if m:
        return "line", parse("generic", m.group(1))
    if "|" in rest or rest[:1] in "<>=":
        parts = []
        for p in rest.split("|"):
            pm = _FORTI_RANGE.fullmatch(p.strip())
            if not pm or not (pv := parse("generic", pm.group(2))):
                return "bad", None
            parts.append((pm.group(1) or "=", pv))
        return "range", parts
    pv = parse("generic", rest)
    return ("exact", pv) if pv else ("bad", None)


def _forti_hit(kind: str, val, v: V) -> bool | None:
    if kind == "all":
        return True
    if kind == "line":
        return v.startswith(val)
    if kind == "exact":
        return v == val
    if kind == "range":
        for op, b in val:
            ok = {"=": v == b, ">=": v >= b, ">": v > b, "<=": v <= b, "<": v < b}[op]
            if not ok:
                return False
        return True
    return None


def eval_fortinet(product: dict, data: dict, v: V | None) -> Verdict | None:
    names = list(product.get("names") or [])
    prods = data.get("products") or {}
    hit_name = next((n for n in prods if any(n.lower() == x.lower() for x in names)), None)
    if hit_name is None:
        return None
    entry = prods[hit_name]
    affected = [x for x in entry.get("affected") or [] if isinstance(x, str)]
    if not affected:
        return Verdict("not_affected", "line_none") if v is not None else None
    if v is None:
        return Verdict("unversioned", "unversioned")
    fix = _forti_fix(data.get("remediation") or "", hit_name, v)
    unknown = False
    lines_named: list[V] = []
    for expr in affected:
        got = _forti_expr(expr, hit_name)
        if got is None:
            continue
        kind, val = got
        if kind == "line":
            lines_named.append(val)
        elif kind == "range":
            lines_named += [V(b.key[:2], b.text) for _, b in val]
        elif kind == "exact":
            lines_named.append(V(val.key[:2], val.text))
        r = _forti_hit(kind, val, v)
        if r is None:
            unknown = True
        elif r:
            return Verdict("affected", "in_range" if kind != "line" else "line_all", fix)
    for expr in entry.get("not_affected") or []:
        got = _forti_expr(str(expr), hit_name)
        if got and _forti_hit(*got, v):
            return Verdict("not_affected", "line_none" if got[0] in ("line", "all") else "fixed")
    if unknown:
        return Verdict("possible", "unparsed_data", fix)
    if any(v.startswith(ln) for ln in lines_named):
        return Verdict("not_affected", "fixed")  # its line is named, the version lies above the affected range
    if lines_named and all(v > ln for ln in lines_named):
        return Verdict("not_affected", "newer_line")
    return Verdict("possible", "line_not_listed", fix)


def _forti_fix(text: str, name: str, v: V) -> str | None:
    """'FortiOS 7.6: Upgrade to 7.6.7 or above' for the installed line."""
    for line in text.splitlines():
        m = re.match(rf"^\s*{re.escape(name)}\s+([0-9]+\.[0-9]+)\s*:\s*upgrade to\s+([0-9][0-9.]*)", line, re.I)
        if m and (ln := parse("generic", m.group(1))) and v.startswith(ln):
            return m.group(2)
    return None


# ---------------------------------------------------------------- Veeam (security KB articles)


def veeam_name(written: str, names: list[str]) -> bool:
    """A product as a Veeam KB writes it is one of the catalogue product's names: "Veeam Backup Enterprise Manager
    (Veeam Backup & Replication)" is Enterprise Manager and B&R; "&" and "and" are the same."""
    outer = re.sub(r"\s*\([^)]*\)\s*", " ", written or "")
    cands = {" ".join(_norm(c)) for c in [outer, *re.findall(r"\(([^)]*)\)", written or "")] if c.strip()}
    return any(" ".join(_norm(n)) in cands for n in names)


def _vv(scheme: str, text) -> V | None:
    if not isinstance(text, str) or not text:
        return None
    if scheme == "veeam":
        return parse(scheme, text)  # "13.1 Patch 2" is no build – read as 13.1.2 it would decide wrongly
    return parse(scheme, text) or parse("generic", text)


def _veeam_fix(v: V, fixes: list[V]) -> str | None:
    """The build to go to: the first fixed build above the installed one in its line (13.0.3.63 for a 13.0.2), else in
    its major version, else the lowest one above it."""
    above = [f for f in fixes if f > v]
    for n in (2, 1):
        same = [f for f in above if f.key[:n] == v.key[:n]]
        if same:
            return min(same).text
    return min(above).text if above else None


def _veeam_issue(scheme: str, issue: dict, aff: list[dict], fix: list[dict], v: V) -> Verdict:
    """One CVE of a KB article for one installed build. Each affected statement is "up to this build, within these
    release lines" (no line: every earlier build); a build above it in such a line is not affected (the vendor bounds
    it), a line the vendor calls not affected is not, older lines follow the article's note ("Older versions are not
    affected" / "Unsupported versions … should be considered vulnerable"), anything else is "possibly"."""
    fixes = [f for f in (_vv(scheme, r.get("build")) for r in fix) if f is not None]
    fixed_to = _veeam_fix(v, fixes)
    not_lines = [ln for ln in (_vv("generic", x) for x in issue.get("not_lines") or []) if ln is not None]
    unknown = False
    lines_named: list[V] = []
    beyond = False  # in a named line, above its last affected build
    for r in aff:
        up = _vv(scheme, r.get("upto"))
        if up is None:
            unknown = True
            continue
        if not r.get("earlier"):  # this one build
            if v == up:
                return Verdict("affected", "in_list", fixed_to)
            lines_named.append(V(up.key[:2], up.text))
            continue
        lines = [ln for ln in (_vv("generic", x) for x in r.get("lines") or []) if ln is not None]
        if r.get("lines") and not lines:
            unknown = True
            continue
        in_line = any(v.startswith(ln) for ln in lines) if lines else True
        lines_named += lines or [V(up.key[:1], up.text)]
        if in_line and v <= up:
            return Verdict("affected", "in_range", fixed_to)
        if in_line:
            beyond = True
    if any(v.startswith(ln) for ln in not_lines):
        return Verdict("not_affected", "line_none")
    if beyond:
        return Verdict("not_affected", "fixed" if any(f <= v and f.key[:2] == v.key[:2] for f in fixes) else "out_of_range")
    if unknown:
        return Verdict("possible", "unparsed_data", fixed_to)
    if not aff:
        # only the fix is named ("resolved in 12.3.2.4854"): at or above it in its line fixed, below it unknown
        if any(f.key[:2] == v.key[:2] and v >= f for f in fixes):
            return Verdict("not_affected", "fixed")
        return Verdict("possible", "fix_only", fixed_to)
    if lines_named and all(v < ln for ln in lines_named):
        older = issue.get("older")
        if older == "not_affected":
            return Verdict("not_affected", "line_none")
        if older == "affected":
            return Verdict("affected", "older_untested", fixed_to)
        return Verdict("possible", "older_than_listed", fixed_to)
    if lines_named and all(v > ln and not v.startswith(ln) for ln in lines_named):
        return Verdict("not_affected", "newer_line")
    return Verdict("possible", "line_not_listed", fixed_to)


def eval_veeam(product: dict, data: dict, v: V | None) -> Verdict | None:
    """A Veeam KB article for a product: the worst of its CVEs that name the product. An article that names the product
    but no build it can compare: "possibly" (with a version) – never "not affected"."""
    names = [str(n) for n in product.get("names") or []]
    if not names or product.get("adv") != "veeam":
        return None
    scheme = product.get("scheme") or "generic"
    issues = [x for x in data.get("issues") or [] if isinstance(x, dict)]
    mine = []
    for x in issues:
        aff = [r for r in x.get("affected") or [] if isinstance(r, dict) and veeam_name(str(r.get("product") or ""), names)]
        fix = [r for r in x.get("fixed") or [] if isinstance(r, dict) and veeam_name(str(r.get("product") or ""), names)]
        if aff or fix:
            mine.append((x, aff, fix))
    if not mine:
        if data.get("none_affected") and not any(x.get("affected") for x in issues):
            return Verdict("not_affected", "line_none")  # "Veeam products … are not affected" (PHP2Shell)
        if not any(veeam_name(str(n), names) for n in data.get("products") or []):
            return None
        if any(x.get("affected") or x.get("fixed") for x in issues):
            return None  # the article's builds are about other products (an agent CVE in a B&R article)
        return Verdict("unversioned", "unversioned") if v is None else Verdict("possible", "unparsed_data")
    if v is None:
        return Verdict("unversioned", "unversioned")
    best: Verdict | None = None
    fixes: list[V] = []
    for x, aff, fix in mine:
        r = _veeam_issue(scheme, x, aff, fix, v)
        if r.status == "affected" and r.fixed and (f := _vv(scheme, r.fixed)) is not None:
            fixes.append(f)
        best = worst(best, r)
    if best is not None and best.status == "affected" and fixes:
        best = Verdict(best.status, best.reason, max(fixes).text, best.detail)  # the build that fixes every CVE of the article
    return best


# ---------------------------------------------------------------- NVD: CPE configurations


def _cpe_parts(criteria: str) -> list[str]:
    # cpe:2.3:part:vendor:product:version:update:… (colons inside a value are escaped with a backslash)
    return re.split(r"(?<!\\):", criteria)


def cpe_fields(cpe: str) -> list[str]:
    """The fields of a CPE – "cpe:2.3:a:vendor:product:…", "cpe:/a:vendor:product" or the catalogue's "a:vendor:product"
    – split only at the colons between fields (NVD escapes one inside a field: a:mailcow:mailcow\\:_dockerized is the
    product "mailcow:_dockerized"), NVD's escapes removed."""
    t = str(cpe or "")
    t = t[8:] if t.startswith("cpe:2.3:") else t[5:] if t.startswith("cpe:/") else t
    return [re.sub(r"\\(.)", r"\1", f) for f in _cpe_parts(t)]


def cpe_vendor_product(cpe: str) -> str:
    """"vendor:product" of a CPE in any of the forms cpe_fields reads ("" when it has no product)."""
    f = cpe_fields(cpe)
    return f"{f[1]}:{f[2]}" if len(f) >= 3 and f[1] and f[2] else ""


WINDOWS_RELEASE_CPE = re.compile(r"^o:microsoft:windows(?:_|$)")


def product_cpes(product: dict, v: V | None) -> set[str]:
    """part:vendor:product of the product. A Windows build: the CPE of its release instead of the product's Windows
    release CPEs – its other CPEs stay (Azure Local's a:microsoft:azure_stack_hci)."""
    own = {c.replace("\\", "") for c in product.get("cpes") or []}
    if product.get("scheme") == "windows" and v is not None:
        one = windows_cpe(product.get("key", ""), v)
        rest = {c for c in own if not WINDOWS_RELEASE_CPE.match(c)}
        return ({one[8:]} if one else set()) | rest
    return own


def _count_numbers(text: str) -> int:
    return len(re.findall(r"\d+", text))


def eval_configs(product: dict, configs: list, v: V | None) -> Verdict | None:
    scheme = product.get("scheme") or "generic"
    wanted = product_cpes(product, v)
    if not wanted:
        return Verdict("possible", "unknown_build") if v is not None and product.get("scheme") == "windows" else None
    if product.get("scheme") == "windows" and v is not None and windows_cpe(product.get("key", ""), v) is None:
        # a build no Windows release has: only the product's other CPEs (Azure Local) – the release CPEs say nothing
        wanted_unknown = True
    else:
        wanted_unknown = False
    sw_editions: dict[str, set[str]] = {}
    for c, ed in product.get("cpe_editions") or []:
        sw_editions.setdefault(c.replace("\\", ""), set()).add(ed.lower())
    results: list[Verdict] = []
    listed: list[V] = []  # versions named one by one (Cisco lists every affected release)
    starts: list[V | None] = []  # where the ranges begin (None: from the first version)
    decided_not = False
    relevant = False
    dashed = False  # "pan-os:-": the product without a version (NVD's "not applicable") – says nothing about versions
    for cfg in configs or []:
        for node in (cfg.get("nodes") or []) if isinstance(cfg, dict) else []:
            for m in node.get("cpeMatch") or []:
                if not isinstance(m, dict) or not m.get("vulnerable"):
                    continue
                parts = _cpe_parts(str(m.get("criteria") or ""))
                short = ":".join(parts[2:5]).replace("\\", "") if len(parts) >= 7 else ""
                if not short or short not in wanted:
                    continue
                if short in sw_editions and (parts[9] if len(parts) > 9 else "*").lower() not in sw_editions[short]:
                    continue  # Firefox ESR's "esr" edition is not the release channel, Jenkins' "lts" not the weekly line
                ed = _edition_by_cpe(product, parts[5]) or _edition_by_cpe(product, parts[9] if len(parts) > 9 else "")
                if ed is not None and v is not None and not in_edition(scheme, ed, v):
                    continue  # SharePoint 2019's CPE for an installed 2016 build
                relevant = True
                if v is None:
                    continue
                cv, cu = parts[5], parts[6]
                if ed is not None and _edition_by_cpe(product, cv) is ed:
                    cv = "*"  # "sharepoint_server:2019": the edition, not a version – its ranges (if any) decide
                bounds = {k: m.get(k) for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if m.get(k)}
                if cv not in ("*", "-", ""):
                    exact, any_upd = from_cpe(scheme, cv, cu)
                    if exact is None:
                        results.append(Verdict("possible", "unparsed_data"))
                        continue
                    listed.append(exact)
                    n = _count_numbers(cv.replace("\\", ""))
                    if v == exact:
                        results.append(Verdict("affected", "in_list"))
                    elif any_upd and v.key[:n] == exact.key[:n] and any(x for x in v.key[n:]):
                        # "11.2.4 (any hotfix)" for an installed 11.2.4-h23: NVD does not say which hotfix fixed it
                        results.append(Verdict("possible", "imprecise"))
                    continue
                if cv == "-" and not bounds:
                    # not "every version": usually the platform half of a "running on" pairing (PHP on PAN-OS) next
                    # to an explicit list of the affected releases – that list decides; alone at most "possibly"
                    dashed = True
                    continue
                if not bounds:
                    results.append(Verdict("possible", "all_versions"))
                    continue
                parsed = {k: parse(scheme, str(b)) for k, b in bounds.items()}
                if any(p is None for p in parsed.values()):
                    results.append(Verdict("possible", "unparsed_data"))
                    continue
                start = parsed.get("versionStartIncluding") or parsed.get("versionStartExcluding")
                end = parsed.get("versionEndIncluding") or parsed.get("versionEndExcluding")
                starts.append(start)
                lo_ok = start is None or v > start or (v == start and "versionStartIncluding" in parsed)
                hi_ok = end is None or upto(v, end, "versionEndIncluding" in parsed)
                if lo_ok and hi_ok:
                    fix = parsed["versionEndExcluding"].text if "versionEndExcluding" in parsed else None
                    detail = {"after": parsed["versionEndIncluding"].text} if "versionEndIncluding" in parsed else {}
                    results.append(Verdict("affected", "in_range", fix, detail))
                else:
                    decided_not = True
    if not relevant:
        return Verdict("possible", "unknown_build") if wanted_unknown else None
    if v is None:
        return Verdict("unversioned", "unversioned")
    best: Verdict | None = None
    for r in results:
        best = worst(best, r)
    if best is not None:
        return best  # affected – or the data does not decide (possible)
    if dashed and not listed and not decided_not:
        return Verdict("possible", "no_version")
    if listed:
        same_line = [x for x in listed if x.key[:2] == v.key[:2]]
        if v > max(same_line or listed):
            return Verdict("not_affected", "newer_than_listed")
        if not decided_not:
            return Verdict("possible", "not_listed")
    if decided_not:
        if starts and all(s is not None and v < s for s in starts) and not listed:
            return Verdict("possible", "older_than_listed")  # below every range: an old release nobody assessed
        return Verdict("not_affected", "fixed")
    return Verdict("possible", "not_listed")


# ---------------------------------------------------------------- NVD: the CNA's affected data (CVE 5 "affected")


def _cna_names(product: dict) -> list[tuple[str, str]]:
    names = [(str(a), str(b)) for a, b in product.get("cna") or []]
    if names:
        return names
    out = []
    for c in product.get("cpes") or []:
        parts = cpe_fields(c)
        if len(parts) == 3:
            out.append((parts[1].replace("_", " "), parts[2].replace("_", " ")))
    return out


def _cna_version(scheme: str, text) -> V | None:
    if not isinstance(text, str):
        return None
    t = text.strip()
    if t in ("", "*", "0", "n/a", "unspecified", "-"):
        return None
    return bound_v(scheme, t[:-2] if t.endswith(".*") else t)


_OPEN = ("", "0", "*", "n/a", "unspecified")
_OP = re.compile(r"^\s*(>=|<=|>|<|=)\s*([^\s,<>=]+)\s*$")


def _range_row(x: dict) -> dict:
    """A range written into the version field, as GitHub's advisories and many CNAs do (">= 3.2.0, < 4.7.1", "< 25.7.0",
    "<= 2.1", "= 1.4.0") – as the CVE 5 form: version / lessThan / lessThanOrEqual. Read as one version it was
    3.2.0.4.7.1 (anything above 3.2.0 "newer than listed") and "< 25.7.0" the fixed release 25.7.0 itself ("listed as
    affected"). "> a" counts from a (rare – a itself then reads affected rather than missed). Anything else unchanged."""
    text = x.get("version")
    if not isinstance(text, str) or x.get("lessThan") or x.get("lessThanOrEqual") or not text.strip()[:1] in "<>=":
        return x
    lo = hi = hie = eq = None
    for part in text.split(","):
        m = _OP.match(part)
        if m is None:
            return x
        op, val = m.groups()
        if op in (">=", ">"):
            lo = lo or val
        elif op == "<":
            hi = hi or val
        elif op == "<=":
            hie = hie or val
        else:
            eq = eq or val
    if eq and not (lo or hi or hie):
        return {**x, "version": eq}
    if not (hi or hie):
        return x  # only a lower bound: "everything from a on" is no range this reads – left as it was (unparsed)
    out = {k: val for k, val in x.items() if k != "version"}
    out["version"] = lo or "0"
    out["lessThan" if hi else "lessThanOrEqual"] = hi or hie
    return out


def _adp_rows(blocks: list) -> list:
    """CISA's ADP rows for eval_cna: their defaultStatus "affected" sits next to a range and is no statement about every
    other version (GitLab CVE-2024-4835: 15.11 – < 17.0.1, default affected) – read as "unknown"."""
    out = []
    for b in blocks or []:
        if not isinstance(b, dict):
            continue
        rows = [{**a, "defaultStatus": "unknown"} if isinstance(a, dict) and a.get("defaultStatus") == "affected" else a for a in b.get("affectedData") or []]
        out.append({**b, "affectedData": rows})
    return out


def eval_cna(product: dict, affected: list, v: V | None, by: str = BY_VENDOR) -> Verdict | None:
    """CVE 5 affected rows (the CNA's – `by` "vendor" – or CISA's ADP rows, `by` "adp")."""
    return _from(_eval_cna(product, affected, v), by)


def _eval_cna(product: dict, affected: list, v: V | None) -> Verdict | None:
    scheme = product.get("scheme") or "generic"
    names = _cna_names(product)
    results: list[Verdict] = []
    relevant = False
    tops: list[V] = []
    defaults: set[str] = set()
    depth = int(product.get("line_depth") or 0)
    lines_named: set[tuple[int, ...]] = set()  # line_depth: the lines the record has rows for (Exchange's CUs)
    edition_skipped = False
    spoke = False  # a row that speaks for the installed version's edition / line
    for src in affected or []:
        for a in (src.get("affectedData") or []) if isinstance(src, dict) else []:
            if not isinstance(a, dict):
                continue
            vendor, prod = str(a.get("vendor") or ""), str(a.get("product") or "")
            if not any(name_matches(prod, want, vendor) and (_norm(vendor)[:1] == _norm(wv)[:1] or name_matches(vendor, wv)) for wv, want in names):
                continue
            if any(name_matches(prod, n, vendor) for n in product.get("excluded_names") or []):
                continue  # another product the names would take (Dovecot: OX Dovecot Pro)
            raw = [x for x in a.get("versions") or [] if isinstance(x, dict)]
            # commit ranges (the Linux kernel's versionType "git": "6fa01ccd… < 8dbed691…") say nothing about a release –
            # read as versions they were an "affected, fix 8dbed691…" for every kernel; the semver rows decide
            versions = [_range_row(x) for x in raw if str(x.get("versionType") or "").lower() != "git"]
            if raw and not versions:
                continue
            if not any(x.get("status") == "affected" for x in versions) and a.get("defaultStatus") != "affected":
                continue
            relevant = True
            defaults.add(str(a.get("defaultStatus") or "unknown"))
            if v is None:
                continue
            ed = edition_of(product, prod)
            if ed is not None and not in_edition(scheme, ed, v):
                edition_skipped = True
                continue  # SharePoint 2019's row for an installed 2016 build
            matched = False
            row_spoke = False
            above_fix = False  # above the end of an affected range of the installed version's line: fixed there
            # NetScaler writes FIPS/NDcPP builds as lines of their own ("13.1-FIPS"): for a standard build they count
            # only where the record has no standard row for that line (12.1 – then they stay "possibly")
            plain = {k.key[:2] for x in versions if not _FLAVOUR.search(str(x.get("version") or "")) and (k := _cna_version(scheme, x.get("version"))) is not None}
            for x in versions:
                status = x.get("status")
                start_text = x.get("version")
                end_text = x.get("lessThan") or x.get("lessThanOrEqual")
                incl = "lessThanOrEqual" in x and "lessThan" not in x
                flavour = _FLAVOUR.search(f"{start_text} {end_text}")
                if flavour and flavour.group(1).lower() not in v.text.lower():
                    own = _cna_version(scheme, _FLAVOUR.sub("", str(start_text or "")).strip(" -"))
                    if own is None or own.key[:2] != v.key[:2] or own.key[:2] in plain:
                        continue  # 13.1-FIPS next to 13.1 (or another line): says nothing about a standard build
                    results.append(Verdict("possible", "unparsed_data"))  # 12.1: only its FIPS builds are named
                    continue
                base = _FLAVOUR.sub("", str(start_text or "")).strip(" -")
                if end_text and x.get("versionType") == "patch" and base not in _OPEN and str(end_text).strip() != "*" and not str(end_text).strip().startswith(base):
                    # NetScaler: version "14.1", lessThan "8.50" – the build within the line: below 14.1-8.50
                    end_text = f"{base}-{str(end_text).strip()}"
                if end_text:
                    # Dell: lessThan "7.30.10.50 or later" – fixed in that version (or a later one): below it is affected
                    end_text = re.sub(r"(?i)\s+or\s+later\s*$", "", str(end_text))
                    line = str(end_text).strip().endswith(".*")
                    start = _cna_version(scheme, _FLAVOUR.sub("", str(start_text or "")).strip(" -") if flavour else start_text)
                    end = None if str(end_text).strip() == "*" else _cna_version(scheme, end_text)
                    if (start is None and str(start_text or "").strip() not in _OPEN) or (end is None and str(end_text).strip() != "*"):
                        results.append(Verdict("possible", "unparsed_data"))
                        continue
                    if depth and end is not None:
                        lines_named.add(end.key[:depth])
                        if (v.key + (0,) * depth)[:depth] != (end.key + (0,) * depth)[:depth]:
                            continue  # Exchange: the row of 2019 CU15 says nothing about a CU14 build
                    row_spoke = True
                    if end is not None:
                        tops.append(end)
                    inside = (start is None or v >= start) and (end is None or upto(v, end, incl, line))
                    if not inside:
                        if status == "affected" and end is not None and not incl and not line and len(end.key) >= 3 and (start is None or v >= start) and _same_line(v, end):
                            # only an exclusive bound is a fix ("< 12.9.8"); "≤ 12.9.7" or "≤ 12.9.*" names the last
                            # affected release known – above it the defaultStatus still speaks; a two-part end ("< 12.9")
                            # is no fix of the whole major line 12 (12.10.1): the defaultStatus decides
                            above_fix = True  # GitLab ">=12.8, <12.9.8" for 12.9.8, PAN-OS "12.2.0 < 12.2.4" for 12.2.4-h1
                        continue
                    matched = True
                    st = _apply_changes(scheme, status, x.get("changes"), v)
                    if st == "affected":
                        results.append(Verdict("affected", "in_range", end.text if end is not None and not incl and not line else None, {"after": end.text} if incl and end else {}))
                    elif st == "unaffected":
                        results.append(Verdict("not_affected", "fixed"))
                elif x.get("changes") and (start := _cna_version(scheme, start_text)) is not None:
                    # PAN-OS writes "from 12.1.0 on, fixed by hotfix branches" without lessThan
                    row_spoke = True
                    tops.append(start)
                    if v < start or v.key[:2] != start.key[:2]:
                        continue  # from 12.1.0 on – within the 12.1 line
                    matched = True
                    st = _apply_changes(scheme, status, x.get("changes"), v)
                    if st == "affected":
                        fixes = sorted(a for c in x.get("changes") or [] if isinstance(c, dict) and c.get("status") == "unaffected" and (a := _cna_version(scheme, c.get("at"))) is not None and a > v)
                        same = [a for a in fixes if a.key[:3] == v.key[:3]] or [a for a in fixes if a.key[:2] == v.key[:2]]
                        results.append(Verdict("affected", "in_range", same[0].text if same else None))
                    elif st == "unaffected":
                        results.append(Verdict("not_affected", "fixed"))
                else:
                    ev = _cna_version(scheme, start_text)
                    if ev is None:
                        if str(start_text or "").strip() not in _OPEN:
                            results.append(Verdict("possible", "unparsed_data"))
                        continue
                    row_spoke = True
                    tops.append(ev)
                    if v == ev:
                        matched = True
                        # only "unaffected" clears it – "unknown" (or no status) leaves it open
                        if status == "affected":
                            results.append(Verdict("affected", "in_list"))
                        elif status == "unaffected":
                            results.append(Verdict("not_affected", "line_none"))
                        else:
                            results.append(Verdict("possible", "not_listed"))
            spoke = spoke or row_spoke or not versions
            if not matched and above_fix:
                # the fixed release (or a later one) of a line the row names: fixed – not the defaultStatus, which is
                # about the versions the rows do not name (PAN-OS writes "affected" there, its older lines)
                results.append(Verdict("not_affected", "fixed"))
            elif not matched and (row_spoke or not versions or not depth):
                d = a.get("defaultStatus")
                if d == "affected":
                    results.append(Verdict("affected", "default_affected"))
                elif d == "unaffected":
                    results.append(Verdict("not_affected", "out_of_range"))
    if not relevant:
        return None
    if v is None:
        return Verdict("unversioned", "unversioned")
    best: Verdict | None = None
    for r in results:
        best = worst(best, r)
    if best is not None:
        return best
    if edition_skipped and not spoke:
        return Verdict("not_affected", "edition_not_named")  # the record names other editions only (SharePoint 2016/2019, not SE)
    if depth and lines_named and not spoke:
        mine = (v.key + (0,) * depth)[:depth]
        if all(mine > ln for ln in lines_named):
            return Verdict("not_affected", "newer_line")  # Exchange SE for a record of 2019 CU14/CU15 only
        if all(mine < ln for ln in lines_named):
            return Verdict("possible", "older_than_listed")
        return Verdict("possible", "line_not_listed")
    if tops and all(v >= t for t in tops):
        return Verdict("not_affected", "newer_than_listed")
    return Verdict("possible", "not_listed")


def _vendor_ranges(product: dict, affected: list) -> bool:
    """The product's own vendor wrote the CNA rows, with ranges (vendor_unaffected: its "not affected" may outweigh NVD's
    range). The rows' vendor is the catalogue's (its vendor or CNA names – not only a CPE's), and they delimit ranges
    (lessThan / lessThanOrEqual): a CNA listing single versions with defaultStatus "unaffected" (VulDB, MITRE) leaves
    NVD's analysis as it is."""
    names = [str(wv) for wv, _ in product.get("cna") or []] + [n for n in _vendor_names(str(product.get("vendor") or "")) if n]
    if not names:
        return False
    wanted = [w for _, w in _cna_names(product)]
    for src in affected or []:
        for a in (src.get("affectedData") or []) if isinstance(src, dict) else []:
            if not isinstance(a, dict):
                continue
            vendor, prod = str(a.get("vendor") or ""), str(a.get("product") or "")
            if not any(name_matches(prod, w, vendor) for w in wanted) or not any(_same_vendor(vendor, n) for n in names):
                continue
            if any(isinstance(x, dict) and (x.get("lessThan") or x.get("lessThanOrEqual")) for x in (_range_row(r) for r in a.get("versions") or [] if isinstance(r, dict))):
                return True
    return False


def _apply_changes(scheme: str, status, changes, v: V) -> str:
    """CVE 5 "changes" inside a range: from `at` on the status changes. PAN-OS writes hotfix branches there
    (at 11.1.0-h3: unaffected) – a hotfix change only applies to its own base (11.1.0-h4, not 11.1.1). Others write a
    fix per line too (NGINX: at 1.27.4 and at 1.26.3; NGINX Plus: at R32 P1 and R31 P3): a change of the installed
    line decides; without one the changes apply only to a version above all of them (1.28.0) – a 1.27.2 is not fixed
    by 1.26.3."""
    st = str(status or "unknown")
    found: list[tuple[V, str]] = []
    for c in changes or []:
        if not isinstance(c, dict):
            continue
        at = _cna_version(scheme, c.get("at"))
        if at is None:
            continue
        found.append((at, str(c.get("status") or "")))
    found.sort(key=lambda x: x[0])
    if scheme == "panos":
        for at, s in found:
            if at.key[3:4] not in ((), (0,)):
                if v.key[:3] == at.key[:3] and v >= at:
                    st = s
            elif v >= at:
                st = s
        return st
    same = [(at, s) for at, s in found if _same_line(v, at)]
    if not same and not all(v >= at for at, _ in found):
        return st  # between the lines that have a fix: none of them fixes this one
    for at, s in same or found:
        if v >= at:
            st = s
    return st


def _adp_product(product: dict) -> dict:
    """The product as CISA's ADP names it: by its CPEs (vendor "paloaltonetworks", product "pan-os") – the ADP's affected
    rows carry CPE names, not the CNA's."""
    names = []
    for c in product.get("cpes") or []:
        parts = cpe_fields(c)
        if len(parts) == 3:
            names.append((parts[1].replace("_", " "), parts[2].replace("_", " ")))
    return {**product, "cna": names}


def filter_ok(product: dict, data: dict) -> bool:
    """A product sharing its CPEs with others (Windows roles share the Windows Server CPEs): a CVE counts only when its
    description mentions the product's `filter` – one of its alternatives ("Remote Desktop Gateway|Remote Desktop
    Services")."""
    flt = product.get("filter")
    if not flt:
        return True
    desc = (data.get("desc") or "").lower()
    return any(w.strip() and w.strip().lower() in desc for w in str(flt).split("|"))


def eval_cvelist(product: dict, data: dict, v: V | None) -> Verdict | None:
    """A CVE record of cvelistV5: the CNA's affected data decides (the vendor itself, mostly); CISA's ADP enrichment only
    where the CNA does not name the product – its rows are less precise (no hotfix changes, CPE names)."""
    if not filter_ok(product, data):
        return None
    got = eval_cna(product, data.get("cna") or [], v)
    if got is None and data.get("adp") and product.get("cpes"):
        got = eval_cna(_adp_product(product), _adp_rows(data.get("adp")), v, "adp")
    return got


def osv_packages(product: dict, data: dict) -> list[dict]:
    """The packages of an OSV record that are this product (its catalogue `osv` entries: ecosystem and package name)."""
    want = {(str(e).lower(), str(n).lower()) for e, n in product.get("osv") or []}
    if not want:
        return []
    return [p for p in data.get("packages") or [] if isinstance(p, dict) and (str(p.get("ecosystem") or "").split(":")[0].lower(), str(p.get("name") or "").lower()) in want]


def eval_osv(product: dict, data: dict, v: V | None) -> Verdict | None:
    """OSV ranges of the product's packages (ECOSYSTEM/SEMVER events: introduced … fixed / last_affected; GIT ranges are
    never stored). Affected inside a range, not affected when the ranges decide it, possible when a bound cannot be read."""
    pkgs = osv_packages(product, data)
    if not pkgs:
        return None
    if v is None:
        return Verdict("unversioned", "unversioned")
    scheme = product.get("scheme") or "generic"
    best: Verdict | None = None
    named = False
    for p in pkgs:
        if v.text in [str(x) for x in p.get("versions") or []]:
            best = worst(best, Verdict("affected", "in_list"))
        for r in p.get("ranges") or []:
            if not isinstance(r, dict):
                continue
            lo_t, hi_t, last_t = r.get("introduced"), r.get("fixed"), r.get("last_affected")
            lo = None if str(lo_t or "0") in ("0", "") else _v(scheme, str(lo_t))
            hi = _v(scheme, str(hi_t)) if hi_t else None
            last = _v(scheme, str(last_t)) if last_t else None
            if (str(lo_t or "0") not in ("0", "") and lo is None) or (hi_t and hi is None) or (last_t and last is None):
                best = worst(best, Verdict("possible", "unparsed_data"))
                continue
            named = True
            inside = (lo is None or v >= lo) and (hi is None or v < hi) and (last is None or upto(v, last, True))
            if inside:
                best = worst(best, Verdict("affected", "in_range", hi.text if hi is not None else None, {"after": last.text} if last is not None else {}))
    if best is not None:
        if best.status == "affected" and not best.fixed:
            # the fix of the installed line, when another range names one (OSV lists a range per line)
            fixes = [f for p in pkgs for r in p.get("ranges") or [] if isinstance(r, dict) and (f := _v(scheme, str(r.get("fixed") or ""))) is not None and f > v]
            same = [f for f in fixes if f.key[:2] == v.key[:2]]
            if same or fixes:
                best.fixed = min(same or fixes).text
        return best
    return Verdict("not_affected", "fixed") if named else None


def eval_nvd(product: dict, data: dict, v: V | None) -> Verdict | None:
    if not filter_ok(product, data):
        return None
    a = _from(eval_configs(product, data.get("configs") or [], v), "nvd")
    cna, adp = data.get("cna") or [], data.get("adp") or []
    if "adp" not in data and len(cna) > 1:
        cna, adp = cna[:1], cna[1:]  # stored before 0.1.47 (one list, the CNA's block first): the others are ADPs
    b = eval_cna(product, cna, v)
    if b is None and (a is None or a.status == "possible") and adp and product.get("cpes"):
        # CISA's ADP only where the CNA does not name the product and NVD's analysis decides nothing (none, or only
        # "possibly": vCenter's exact update CPEs, CVE-2024-37080 – CISA's "8.0 < 8.0u2d" settles it) – never over a
        # clear NVD verdict (VMware Cloud Foundation CVE-2022-22948: CISA "4.0 – < 5.0", NVD "< 4.4.1")
        b = eval_cna(_adp_product(product), _adp_rows(adp), v, "adp")
    if a is None or b is None:
        return a or b
    if a.status == "affected" and b.status == "not_affected" and b.reason in ("out_of_range", "fixed") and b.detail.get("by") == BY_VENDOR and _vendor_ranges(product, cna):
        # the vendor names its affected ranges and says this version is not affected – outside of them with every
        # other version "unaffected" (defaultStatus), or the fix of its line (GitLab CVE-2026-84284: "19.3 < 19.3.6"
        # for 19.3.7) –, NVD's range takes in more (PAN-OS CVE-2026-0262: NVD "< 10.2.7", the vendor 10.2 on only;
        # GitLab: NVD "< 19.4.2"): one says no, the other yes – "possibly", with both named
        return Verdict("possible", "vendor_unaffected", a.fixed, {"by": "nvd"})
    if a.status == "affected" or b.status == "affected":
        return a if a.status == "affected" else b
    if b.status == "not_affected" and a.status in ("possible", "not_affected"):
        return b  # the CNA (mostly the vendor itself) decides where NVD's CPEs are less precise
    if a.status == "not_affected" and b.status == "possible" and b.reason == "unparsed_data":
        return a  # the CNA wrote prose ("versions prior to v22.09"): NVD's analysed ranges decide (BookStack CVE-2022-40690)
    return worst(a, b)


# ---------------------------------------------------------------- CSAF advisories (BSI, Siemens, Cisco): ranges per product

def range_of(text: str) -> dict | None:
    """'<19.5.1' → {to}, '>=7.6.1|<=7.6.6' → {from, to}, 'vers:intdot/>=1.0|<2.0', 'vers:all/*' → {all}, '17.2.6' → {exact}.
    One range: a text with several of them gives its first (ranges_of gives all)."""
    got = ranges_of(text)
    return got[0] if got else None


def _starts_new(out: dict, key: str, ver: str) -> bool:
    """Whether a bound / an exact version begins the next range of a text with several (ranges_of)."""
    if key in out:
        return True  # a second end, a second start, a second exact version
    if key == "exact":
        return "from" in out or "to" in out
    if "exact" in out:
        return True
    if key == "from" and "to" in out:
        # 'vers:intdot/>=1.2.0|<1.2.5|>=1.2.8|<1.2.9': a start at or after the end – the next interval ('<=7.4.8, >=7.4.5'
        # written the other way round stays one)
        start, end = _v("generic", ver), _v("generic", out["to"])
        return start is None or end is None or start >= end
    return False


def ranges_of(text: str) -> list[dict]:
    """The ranges of one version text, as range_of – but a text with several of them ('vers:intdot/>=1.2.0|<1.2.5|>=1.2.8|
    <1.2.9': two intervals, '<19.5.1, <19.4.3': two lines, '2.4.1|2.4.3': two versions) gives each of them, not only
    the last one. [] when it cannot be read."""
    t = (text or "").strip()
    if len(t) > VTEXT_MAX:
        return []  # no range anyone wrote – and splitting it would be quadratic
    t = re.sub(r"^vers:[a-z]+/", "", t)
    if t in ("*", "all", "") or re.fullmatch(r"(?i)all\s+versions?", t):
        return [{"all": True, "text": "alle Versionen" if t else ""}]
    if m := re.fullmatch(r"(?i)(\d+(?:\.\d+)*)\s+all\s+versions?", t):
        return [{"line": m.group(1), "text": f"{m.group(1)}.x"}]
    found: list[dict] = []
    parts: list[list[str]] = [[]]  # the written parts of each range (its text when there are several)
    out: dict = {"text": text.strip()[:80]}
    for part in re.split(r"\s*[|,]\s*|\s+(?=[<>=])", t):
        m = re.fullmatch(r"(<=|>=|<|>|=)?\s*([0-9][0-9A-Za-z.\-_()+ ]*?)", part.strip())
        if not m:
            return []
        op, ver = m.group(1) or "=", m.group(2).strip()
        key = "to" if op in ("<", "<=") else "from" if op in (">=", ">") else "exact"
        if _starts_new(out, key, ver):
            found.append(out)
            out = {"text": ""}
            parts.append([])
        parts[-1].append(part.strip())
        if key == "to":
            out |= {"to": ver, "to_incl": op == "<="}
        elif key == "from":
            out |= {"from": ver, "from_incl": op == ">="}
        else:
            out["exact"] = ver
    found.append(out)
    if len(found) > 1:
        for r, written in zip(found, parts, strict=True):
            r["text"] = " ".join(written)[:80]
    return found


def _v(scheme: str, text: str | None) -> V | None:
    if not text:
        return None
    return bound_v(scheme, text)


def eval_ranges(scheme: str, entry: dict, v: V | None) -> Verdict | None:
    """One product of a CSAF document against an installed version. Upper bounds without a start are per line
    (BSI: "<19.5.1, <19.4.3": a 19.4.5 is fixed, a 19.5.0 is not); exact versions are a list (Cisco)."""
    ranges = [r for r in entry.get("affected") or [] if isinstance(r, dict)]
    fixed = [x for x in (_v(scheme, f) for f in entry.get("fixed") or []) if x is not None]
    if not ranges:
        return None
    if v is None:
        return Verdict("unversioned", "unversioned")
    if any(f == v for f in fixed):
        return Verdict("not_affected", "fixed")
    for n in entry.get("not_affected") or []:
        for r in ranges_of(n):
            ln = _v(scheme, r.get("line")) if r.get("line") else None
            if (ln is not None and v.startswith(ln)) or (r.get("exact") and _v(scheme, r["exact"]) == v):
                return Verdict("not_affected", "line_none" if ln is not None else "fixed")
    named: list[V] = []  # the release lines the document speaks about
    best: Verdict | None = None
    uppers: list[tuple[V, bool]] = []
    exacts: list[V] = []
    for r in ranges:
        if r.get("all"):
            best = worst(best, Verdict("affected", "all_listed"))
            continue
        if r.get("line"):
            ln = _v(scheme, r["line"])
            if ln is None:
                best = worst(best, Verdict("possible", "unparsed_data"))
            elif v.startswith(ln):
                best = worst(best, Verdict("affected", "line_all"))
            continue
        lo, hi = _v(scheme, r.get("from")), _v(scheme, r.get("to"))
        named += [x for x in (lo, hi, _v(scheme, r.get("exact")), _v(scheme, r.get("line"))) if x is not None]
        if (r.get("from") and lo is None) or (r.get("to") and hi is None):
            best = worst(best, Verdict("possible", "unparsed_data"))
            continue
        if r.get("exact"):
            ex = _v(scheme, r["exact"])
            if ex is None:
                best = worst(best, Verdict("possible", "unparsed_data"))
            else:
                exacts.append(ex)
                if ex == v:
                    best = worst(best, Verdict("affected", "in_list"))
            continue
        if lo is None and hi is not None:
            uppers.append((hi, bool(r.get("to_incl"))))
            continue
        inside = (lo is None or v > lo or (v == lo and r.get("from_incl", True))) and (hi is None or upto(v, hi, bool(r.get("to_incl"))))
        if inside:
            best = worst(best, Verdict("affected", "in_range", None if r.get("to_incl") or hi is None else hi.text))
    if uppers:
        same = [(h, incl) for h, incl in uppers if h.key[:2] == v.key[:2]]
        if same:
            if any(upto(v, h, incl) for h, incl in same):
                fix = min((h for h, incl in same if not incl and v < h), default=None)
                best = worst(best, Verdict("affected", "in_range", fix.text if fix else None))
            else:
                best = worst(best, Verdict("not_affected", "fixed"))
        elif all(v > h for h, _ in uppers):
            best = worst(best, Verdict("not_affected", "newer_line"))
        else:
            best = worst(best, Verdict("possible", "line_not_listed"))
    if best is not None and best.status == "affected" and not best.fixed:
        cand = [f for f in fixed if f > v]
        same = [f for f in cand if f.key[:2] == v.key[:2]]
        if cand:
            best.fixed = min(same or cand).text
    if best is None and exacts:
        same = [x for x in exacts if x.key[:2] == v.key[:2]]
        if v > max(same or exacts):
            return Verdict("not_affected", "newer_than_listed")
        return Verdict("possible", "not_listed")
    if best is None:
        same_fix = [f for f in fixed if f.key[:2] == v.key[:2]]
        if same_fix and v >= min(same_fix):
            return Verdict("not_affected", "fixed")
        if uppers:
            return Verdict("possible", "not_listed")
        if any(x.key[:2] == v.key[:2] for x in named):
            return Verdict("not_affected", "out_of_range")  # its line is named, the version lies outside the range
        if named and all(v > x for x in named):
            return Verdict("not_affected", "newer_line")
        return Verdict("possible", "line_not_listed")
    return best


def _provider(key: str) -> dict | None:
    from app import vendor_catalog

    return next((p for p in vendor_catalog.CSAF_PROVIDERS if p["key"] == key), None)


def _same_vendor(a: str, b: str) -> bool:
    """Two vendor names for the same company (as eval_cna compares them): the same first word, or one names the other."""
    na, nb = _norm(a), _norm(b)
    return bool(na and nb) and (na[:1] == nb[:1] or name_matches(a, b) or name_matches(b, a))


def _vendor_names(vendor: str) -> list[str]:
    """A catalogue vendor and the names in it: "Splunk (Cisco)" → Splunk (Cisco), Splunk, Cisco – a Cisco document may
    list a Splunk product in its Cisco or in a Splunk branch."""
    m = re.match(r"^(.*?)\s*\((.+)\)\s*$", vendor)
    return [vendor, m.group(1), m.group(2)] if m else [vendor]


def csaf_speaks_for(product: dict, data: dict) -> bool:
    """A CSAF provider's document (data["provider"], csaf.yaml) speaks only for the products of the vendors csaf.yaml
    maps the provider to – a Schneider Electric server never decides about Apache Tomcat (security review 0.1.26 H1).
    Documents without a provider (BSI, the stories' own CSAF) are not limited here."""
    key = data.get("provider")
    if not key:
        return True
    prov = _provider(str(key))
    if prov is None:
        return False  # a provider no longer in csaf.yaml: its documents speak for nobody
    pv = str(product.get("vendor") or "").strip().lower()
    return bool(pv) and pv in {v.lower() for v in prov["vendors"]}


def entries_for(product: dict, data: dict) -> list[dict]:
    """The products of a CSAF document that are this catalogue product – by CPE, else by name. A provider's document:
    only for its own vendors' products, and only entries in the product's vendor branch (csaf_speaks_for)."""
    if not csaf_speaks_for(product, data):
        return []
    own = str(product.get("vendor") or "") if data.get("provider") else ""
    cpes = {cpe_vendor_product(c) for c in product.get("cpes") or []} - {""}
    names = [(str(a), str(b)) for a, b in product.get("cna") or []] + [("", str(product.get("label") or ""))]
    names += [("", re.sub(r"\s*\(.*?\)\s*$", "", str(product.get("label") or "")))]
    excluded = [str(n) for n in product.get("excluded_names") or []]
    out = []
    for e in data.get("products") or []:
        if own and not any(_same_vendor(str(e.get("vendor") or ""), o) for o in _vendor_names(own)):
            continue  # another vendor's branch in a provider's document
        if excluded and any(name_matches(str(e.get("name") or ""), n, str(e.get("vendor") or "")) for n in excluded):
            continue  # another product under the same CPE (Dovecot: OX Dovecot Pro)
        cpe = e.get("cpe") or ""
        if cpe and cpe_vendor_product(cpe) in cpes:  # an escaped colon stays in its field (mailcow:_dockerized)
            out.append(e)
            continue
        if not cpe and any(w and name_matches(str(e.get("name") or ""), w, str(e.get("vendor") or "")) for _, w in names):
            out.append(e)
    return out


# CSAF publishers that are the vendor itself (the stories' own documents of Siemens, Cisco, Fortinet – older records
# without the provider key); every other provider-less document comes from a coordinator (the BSI's WID)
VENDOR_PUBLISHERS = ("siemens", "cisco", "fortinet")


def csaf_by(data: dict) -> str:
    """Who speaks in a CSAF document: "vendor" (a CSAF provider of csaf.yaml – its documents are checked to be its own
    –, or a vendor's document that came with a story), "bsi" (CERT-Bund's WID documents) or "csaf" (another publisher)."""
    if data.get("provider"):
        return BY_VENDOR
    pub = str(data.get("publisher") or "").strip().lower()
    if pub.startswith("bsi") or str(data.get("kind") or "") == "bsi":
        return "bsi"
    if any(pub.startswith(n) for n in VENDOR_PUBLISHERS) or str(data.get("kind") or "") in VENDOR_PUBLISHERS:
        return BY_VENDOR
    return "csaf"


def eval_csaf(product: dict, data: dict, v: V | None) -> Verdict | None:
    best = None
    for e in entries_for(product, data):
        best = worst(best, eval_ranges(product.get("scheme") or "generic", e, v))
    return _from(best, csaf_by(data))


def with_third_party(own: Verdict | None, records: Verdict | None, complete: bool = True) -> Verdict | None:
    """A third party's verdict (a BSI document: csaf_by "bsi"/"csaf") next to the CVE records of its CVEs (the CNA –
    the vendor –, the NVD, CISA, OSV): the third party sums up several CVEs and the vendors' data, it does not decide
    against them.
    - "every version affected" without a version (all_listed) against records that say "not affected": "possibly",
      with the source named (BSI lists "Red Hat Enterprise Linux" for a package of it)
    - "not affected" against records that say "affected": the records (BSI's per-line bounds "<3.16.0, <3.15.2"
      merge two CVEs – one of them affects 3.15.2, CVE-2026-103995)
    - "possibly" (or nothing): the records where they decide – their "not affected" only when `complete`: every CVE
      of the document has a record that judged the product (a CVE without one, or whose record does not name the
      product, may be the one that affects the version: the third party's "possibly" stays)
    Otherwise the third party's verdict stays (its range, where the records do not decide)."""
    if own is None:
        return records
    if records is None:
        return own
    who = own.detail.get("by")
    if own.status == "affected" and own.reason == "all_listed":
        if records.status == "not_affected":
            return Verdict("possible", "all_listed_disputed", None, {"by": who} if who else {})
        if records.status == "affected":
            return records  # the records' range (with its fix) is more precise than "every version"
        return own
    if own.status == "not_affected" and records.status == "affected":
        return records
    if own.status not in ("affected", "not_affected") and (records.status == "affected" or (records.status == "not_affected" and complete)):
        return records
    return own



VEEAM_TOP = 10**9  # "every build of 12.3.2": 12.3.2.0 … 12.3.2.<this>
_TOKEN = re.compile(r"(?<![\w.])v?\d{1,9}(?:\.\d{1,9})+(?:[-.]?[a-z]{1,2}\d{1,6})?", re.I)


def _depth(product: dict) -> int:
    """0: unknown (no release data) – no version is short then (as vendor.short_version)."""
    from app import vendor_catalog  # the release lines say how long a complete version is

    if (product.get("scheme") or "generic") == "veeam":
        return VEEAM_BUILD_DEPTH  # a complete Veeam build has four parts (as the form says)
    return vendor_catalog.want_depth(product) or 0


def _short_probes(scheme: str, data: dict, v: V, depth: int) -> list[V]:
    """The versions a short version ("7.4", "1.25") stands for that the data can tell apart: the first and the last
    possible one, and every version the data names inside it with its neighbours (a range 7.4.5–7.4.8 inside "7.4").
    Empty: the data names nothing more precise than the version – it decides as it is."""
    import json

    inside: set[tuple[int, ...]] = set()
    for tok in set(_TOKEN.findall(json.dumps(data, default=str))):
        t = parse(scheme, tok) or parse("generic", tok)
        if t is not None and t.depth > v.depth and t.startswith(v):
            inside.add(t.key)
    if not inside:
        return []
    deep = max(depth, *(len(k) for k in inside))
    keys = {v.key + (0,) * (deep - v.depth), v.key + (VEEAM_TOP,) * (deep - v.depth)}
    for k in inside:
        keys |= {k, k[:-1] + (k[-1] + 1,)}
        if k[-1] > 0:
            keys.add(k[:-1] + (k[-1] - 1,))
    return [V(k, v.text) for k in sorted(keys)]


def evaluate(product: dict, source: str, data: dict, version: str | None) -> Verdict | None:
    """The verdict of one advisory for one product and (optional) version. None: the advisory does not concern it.
    A stored version is compared as the product's rules read it (app/version_input.py: "2019 CU15" for Exchange is
    15.2.1748, "iLO 6 v1.62" is 1.62) – one the rules refuse is not compared ("möglicherweise betroffen")."""
    scheme = product.get("scheme") or "generic"
    if version:
        version = version_input.effective(product, version)
        if version is None:
            base = evaluate(product, source, data, None)
            return _like(base, "possible", "unparsed_version") if base is not None and base.status != "not_affected" else base
    v = parse(scheme, version) if version else None
    if scheme == "cisco" and v is not None and ios_classic(v.text):
        # classic IOS (15.9(3)M9): compared within its train only – a listed release says "affected", nothing says
        # "not affected" (the next train may be unassessed)
        got = _evaluate(product, source, data, v)
        if got is not None and got.status == "not_affected":
            return _like(got, "possible", "ios_train")
        return got
    if version and v is None and scheme not in ("cloud",):
        # a version we cannot compare: never "not affected" – but only for advisories that concern the product at all
        base = evaluate(product, source, data, None)
        return _like(base, "possible", "unparsed_version") if base is not None and base.status != "not_affected" else base
    if scheme == "veeam" and v is not None and v.depth < VEEAM_BUILD_DEPTH:
        # "12.3.2" without its build: decided only where the first and the last build of 12.3.2 get the same verdict
        pad = VEEAM_BUILD_DEPTH - v.depth
        lo = _evaluate(product, source, data, V(v.key + (0,) * pad, v.text))
        hi = _evaluate(product, source, data, V(v.key + (VEEAM_TOP,) * pad, v.text))
        if lo is None or hi is None or lo.status == hi.status:
            return lo or hi
        return _like(lo, "possible", "build_needed", lo.fixed or hi.fixed)
    if v is not None and scheme not in ("panos", "windows", "ivanti", "cloud", "distro", "sap") and v.depth < (depth := _depth(product)):
        # a short version ("7.4" for FortiOS, "1.25" for nginx) stands for every release inside it: decided only where
        # all of them the data can tell apart get the same verdict – never "not affected" because 7.4 = 7.4.0 is
        probes = _short_probes(scheme, data, v, depth)
        if probes:
            got = [_evaluate(product, source, data, p) for p in probes]
            known = [g for g in got if g is not None]
            if not known:
                return None
            if len({g.status for g in known}) == 1 and len(known) == len(got):
                return known[0]
            fix = next((g.fixed for g in known if g.status == "affected" and g.fixed), None)
            return _like(next((g for g in known if g.status == "affected"), known[0]), "possible", "short_version", fix)
    return _evaluate(product, source, data, v)


def _evaluate(product: dict, source: str, data: dict, v: V | None) -> Verdict | None:
    scheme = product.get("scheme") or "generic"
    if source == "veeam":
        return _from(eval_veeam(product, data, v), BY_VENDOR)
    if source == "paloalto":
        return _from(eval_paloalto(product, data, v), BY_VENDOR)
    if source == "fortinet":
        return _from(eval_fortinet(product, data, v), BY_VENDOR)
    if source == "csaf":
        return eval_csaf(product, data, v)
    if source == "nvd":
        if scheme == "cloud":
            r = eval_nvd(product, data, None)
            return _like(r, "service", "cloud") if r is not None else None
        return eval_nvd(product, data, v)
    if source == "cvelist":
        if scheme == "cloud":
            r = eval_cvelist(product, data, None)
            return _like(r, "service", "cloud") if r is not None else None
        return eval_cvelist(product, data, v)
    if source == "osv":
        return _from(eval_osv(product, data, v), "osv") if scheme != "cloud" else None
    return None
