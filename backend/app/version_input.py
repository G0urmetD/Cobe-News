"""The version an admin types for a product – checked and turned into the form advisories compare, per product.

The version schemes (app/vendor_versions.py) know how versions of a kind are written; a product knows more: its own name
in front of the version ("iLO 6 v1.62"), display forms of its vendor ("NS14.1: Build 29.72.nc"), names that stand for
builds (Exchange "2019 CU15 Apr25HU", app/build_maps.py), which forms belong to a product split off from it (pfSense
Plus 24.11 typed for pfSense CE) and which release lines exist at all. `check` applies, in this order:

1. ``belongs``   a typed form of another product (catalogue `belongs`) → refused: other_product (+ that product)
2. its name      the product's label, aliases and vendor in front of the version are dropped
3. ``normalize`` the product's display-form rules (two_digit_year, netscaler, ise_patch, office_build, nginx_plus, horizon_yymm …)
4. build table   a name or build looked up (vCenter/ESXi, Exchange, SQL Server, VMware Tools, GlobalProtect)
5. the scheme    vendor_versions.validate – strict about words of their own before numbers
6. ``pattern``   the catalogue's regular expression for the product (Exchange: builds only)
7. plausibility  the major version must be on a release line the product has (endoflife.date's lines and latest
                 releases): "2019 CU15", "2411", "12416" or "2024.005.20320" are far beyond every line of
                 Exchange (15), Office (16), VMware Tools (13) or Acrobat (25) → refused: implausible. A product
                 marked ``lines_only`` (Firefox ESR, Jenkins LTS: ``lts``) has only some of the lines – a version
                 between them that is on none ("134.0" for Firefox ESR: 115, 128, 140, 153) is refused as well

What is stored is the result (`value`); the form says what it became ("→ 15.2.1748.24"). Stored versions are evaluated
through `effective` – the same steps, so a version stored before a rule existed is compared as it is meant
("2019 CU15" → 15.2.1748) or, when a rule refuses it, not compared at all ("möglicherweise betroffen") and shown with
its reason ("bitte prüfen") – never dropped.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache

from app import build_maps, vmware_builds
from app.vendor_versions import MAX_LEN, parse, validate

# reasons whose version is not compared at all when it is stored (the rule says it means something else)
HARD = frozenset({"other_product", "unknown_build", "build_mismatch", "unknown_name", "implausible", "pattern"})
# schemes whose versions are no release line of their own (Windows builds, distributions) or checked by their table
NO_LINES = frozenset({"windows", "distro", "cloud", "vmware", "panos"})
INPUT_MAX = 200  # a pasted line (SELECT @@VERSION, nginx -v) – the version taken from it is at most MAX_LEN
PLAUSIBLE_FACTOR = 1.5  # a major far beyond every known line: 1.5× the highest and 10 more
PLAUSIBLE_MARGIN = 10


@dataclass(frozen=True)
class Checked:
    ok: bool
    value: str  # what is stored and compared (looked up / normalised) – or the typed text when refused
    reason: str = ""  # "" | empty | too_long | kb | format | cloud | unknown_build | build_mismatch | unknown_name | other_product | pattern | implausible
    mapped: bool = False  # the value is not what was typed (looked up or normalised): the form shows "→ value"
    hint: str | None = None  # key of a texts.yaml hint that explains the reason
    to: str | None = None  # other_product: the product it belongs to
    lines: tuple[str, ...] = field(default=())  # implausible: the release lines the product has


def _clean(text: str) -> str:
    """The typed text as a version: compatibility forms folded (NFKC – full-width "３.９.０" is 3.9.0), invisible format
    and direction characters (Unicode Cf: U+202E, zero-width spaces …) and other control characters dropped, blanks
    collapsed. 0.1.50 kept them: "3.9.0" + U+202E was stored as a version of its own that looked like 3.9.0."""
    t = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text or ""))
    return "".join(c for c in t if unicodedata.category(c) not in ("Cf", "Cc")).strip()


# ---------------------------------------------------------------- 2. the product's own name


def _names(product: dict) -> list[str]:
    """Names that may stand in front of a version: label (also without vendor and bracket), aliases, keywords."""
    label = str(product.get("label") or "")
    vendor = str(product.get("vendor") or "")
    out = [label, re.sub(r"\s*\([^)]*\)", "", label)]
    out += [x for b in re.findall(r"\(([^)]*)\)", label) for x in [b, *b.split(",")]]  # "Cisco Meraki (MS, MR, MX)"
    for n in list(out):
        if vendor and n.lower().startswith(vendor.lower() + " "):
            out.append(n[len(vendor) + 1 :])
    out += [str(a) for a in product.get("aliases") or []] + [str(k) for k in product.get("kw") or []]
    return sorted({n.strip() for n in out if n and len(n.strip()) >= 2}, key=len, reverse=True)


def strip_name(product: dict, text: str) -> str:
    """'HPE iLO 6 v1.62' → 'v1.62', 'SFOS 21.0.1 MR-1-Build272' → '21.0.1 MR-1-Build272' – only when a version is left."""
    t = text
    vendor = str(product.get("vendor") or "")
    for word in [vendor, re.sub(r"\s*\(.*?\)\s*", " ", vendor).strip()]:
        if word and t.lower().startswith(word.lower() + " "):
            t = t[len(word) + 1 :].lstrip()
            break
    for n in _names(product):
        if t.lower().startswith(n.lower()):
            rest = t[len(n) :]
            if rest[:1] in (" ", ":", "/", "_", ",") or (rest[:1] == "-" and rest[1:2].isalpha()) or (rest[:1].lower() == "v" and rest[1:2].isdigit()):
                rest = rest.lstrip(" :/_,-")
                if re.search(r"\d", rest):
                    return rest
    return t if re.search(r"\d", t) else text


# ---------------------------------------------------------------- 3. display forms of a product


def _two_digit_year(t: str) -> str:
    """Adobe Acrobat/Reader: Help → About may show 2024.005.20320 – advisories write 24.005.20320."""
    m = re.fullmatch(r"(?i)v?20(\d{2})(\.\d{3}\.\d{4,6})", t)
    return f"{m.group(1)}{m.group(2)}" if m else t


def _netscaler(t: str) -> str:
    """NetScaler: "NS14.1: Build 29.72.nc" (show version, GUI) → 14.1-29.72 – the form of the advisories."""
    m = re.fullmatch(r"(?i)(?:netscaler\s+)?(?:ns)?(\d{2}\.\d)\s*[:,]?\s*build\s*(\d{1,3}\.\d{1,3})(?:\.nc)?(?:\s*(fips|ndcpp))?", t)
    if m:
        return f"{m.group(1)}-{m.group(2)}" + (f" {m.group(3).upper()}" if m.group(3) else "")
    return t


def _ise_patch(t: str) -> str:
    """Cisco ISE: "3.2.0.542 Patch 5" (show version: build and patch) → "3.2 Patch 5" as Cisco's records write it; the
    build number is no part of the version."""
    m = re.fullmatch(r"(?i)(\d+)\.(\d+)(?:\.0)?(?:\.\d{2,5})?\s*(?:,?\s*(?:patch|p)\s*(\d{1,2}))?", t)
    if not m:
        return t
    return f"{m.group(1)}.{m.group(2)}" + (f" Patch {m.group(3)}" if m.group(3) else ".0")


def _office_build(t: str) -> str:
    """Office: File → Account shows "Version 2411 (Build 18227.20162 Click-to-Run)" – the version advisories compare is
    16.0.18227.20162 (the "2411" alone says nothing comparable)."""
    m = re.search(r"(?i)\bbuild\s*(\d{4,5}\.\d{4,5})\b", t)
    if m:
        return f"16.0.{m.group(1)}"
    m = re.fullmatch(r"(\d{5}\.\d{5})", t)
    return f"16.0.{m.group(1)}" if m else t


def _nginx_plus(t: str) -> str:
    """NGINX Plus: nginx -v says "nginx/1.27.2 (nginx-plus-r33)" or "nginx-plus-r33-p1" – the release is R33 (P1)."""
    m = re.search(r"(?i)nginx-plus-r(\d{1,3})(?:-p(\d{1,2}))?", t) or re.fullmatch(r"(?i)r\s*(\d{1,3})(?:\s*-?\s*p\s*(\d{1,2}))?", t)
    if m:
        return f"R{m.group(1)}" + (f" P{m.group(2)}" if m.group(2) else "")
    return t


def _checkpoint(t: str) -> str:
    """Check Point: "R81.20 JHF Take 99" / "R81.20 Jumbo Hotfix Take 99" → "R81.20 Take 99"; "R81.20 - Build 012" is
    the build of the release (not a take) → "R81.20"."""
    t = re.sub(r"(?i)\s*(?:jhf|jumbo\s+hotfix(?:\s+accumulator)?)\s+(?=take\b)", " ", t)
    return re.sub(r"(?i)\s*-?\s*build\s*\d{1,4}$", "", t).strip()


def _horizon_yymm(t: str) -> str:
    """Omnissa Horizon 8: the releases are named by year and month – "2412", "2412.1", "Horizon 8 2412" – and
    endoflife.date's lines (and the 8.x CPE versions of NVD) write them 8.2412 / 8.2412.1: stored in that form, so lines,
    support dates and NVD's 8.x bounds compare."""
    m = re.fullmatch(r"(?i)(?:horizon\s*)?(?:8\s*[. ]\s*)?(2\d{3})((?:\.\d{1,2})*)(?:\s*\(?esb\)?)?", t)
    if m and 1 <= int(m.group(1)[2:]) <= 12:
        return f"8.{m.group(1)}{m.group(2)}"
    return t


def _leading_zeros(t: str) -> str:
    """Exchange: ExSetup.exe's FileVersion (and Microsoft's CVE records) write "15.02.1748.024" – the build tables, the
    advisories' ranges and the form write 15.2.1748.24. Only a version of numbers alone."""
    if re.fullmatch(r"\d{1,6}(?:\.\d{1,6}){1,4}", t):
        return ".".join(str(int(x)) for x in t.split("."))
    return t


def _ipfire_core(t: str) -> str:
    """IPFire: the web UI and the release notes write "IPFire 2.27 (x86_64) - Core Update 174" – stored in the form the
    NVD's CPEs are read as (vendor_versions.from_cpe): "2.27 Core 174"."""
    m = re.fullmatch(r"(?i)(?:ipfire\s*)?v?(\d+\.\d+)\s*(?:\((?:x86_64|aarch64|arm\w*|i586)\))?\s*[-–,]?\s*core(?:\s*-?\s*update)?\s*(\d{1,4})", t)
    return f"{m.group(1)} Core {m.group(2)}" if m else t


NORMALIZE = {
    "two_digit_year": _two_digit_year,
    "netscaler": _netscaler,
    "ise_patch": _ise_patch,
    "office_build": _office_build,
    "nginx_plus": _nginx_plus,
    "checkpoint": _checkpoint,
    "horizon_yymm": _horizon_yymm,
    "leading_zeros": _leading_zeros,
    "ipfire_core": _ipfire_core,
}


# ---------------------------------------------------------------- 7. plausibility


def known_majors(product: dict) -> tuple[set[int], list[str]]:
    """The major versions of the product's release lines (endoflife.date): from their latest releases where they name
    one (SQL Server's lines are "2022", its versions 16.0.x), else from the lines' names."""
    from app import vendor_catalog

    scheme = product.get("scheme") or "generic"
    rels = vendor_catalog.releases(product.get("eol"))
    names = [str(r.get("name") or "") for r in rels]

    def major(text: str) -> int | None:
        v = parse(scheme, text) or parse("generic", text)
        if v is None and (lead := vendor_catalog.lead(text)):
            v = parse("generic", lead)
        return v.key[0] if v is not None and v.key else None

    latest = {m for r in rels if r.get("latest") and (m := major(str(r["latest"]))) is not None}
    majors = latest or {m for n in names if (m := major(n)) is not None}
    return majors, names[:6]


def example_for(product: dict) -> str:
    """The example the form and its hints show: the product's own, else the latest release of its newest line
    (endoflife.date – an example on one of the lines the hint names), else the scheme's generic one."""
    from app import vendor_catalog
    from app.vendor_versions import EXAMPLES

    if product.get("example"):
        return str(product["example"])
    scheme = product.get("scheme") or "generic"
    for r in vendor_catalog.releases(product.get("eol")):
        latest = str(r.get("latest") or "")
        if latest and parse(scheme, latest) is not None:
            return latest
    return EXAMPLES.get(scheme, "")


def _line_key(scheme: str, name: str) -> tuple[int, ...] | None:
    """The numbers of a line's name ("153" → (153,), "2.568" → (2, 568)) – None for a name without them."""
    from app import vendor_catalog

    v = parse(scheme, name) or parse("generic", name)
    if v is None and (lead := vendor_catalog.lead(name)):
        v = parse("generic", lead)
    return tuple(v.key) if v is not None and v.key else None


def own_lines(product: dict) -> tuple[list[tuple[int, ...]], list[str], tuple[int, ...] | None]:
    """`lines_only`: the product's own lines of its release data (`lts`: those endoflife.date marks LTS – Firefox ESR's
    115/128/140/153 among all Firefox lines, Jenkins' 2.568/2.555/… among the weekly line; `all`: every listed line),
    their names (newest first) and the newest line of the release data at all (the upper end of what the data knows)."""
    from app import vendor_catalog

    mode = product.get("lines_only")
    if mode not in ("lts", "all"):
        return [], [], None
    scheme = product.get("scheme") or "generic"
    rels = vendor_catalog.releases(product.get("eol"))
    keys, names, every = [], [], []
    for r in rels:
        k = _line_key(scheme, str(r.get("name") or ""))
        if k is None:
            continue
        every.append(k)
        if mode == "all" or r.get("isLts"):
            keys.append(k)
            names.append(str(r["name"]))
    return keys, names, (max(every) if every else None)


def _on_own_line(product: dict, v) -> tuple[bool, tuple[str, ...]]:  # noqa: ANN001
    """A version of a `lines_only` product: on one of its lines – or outside what the release data knows (older than
    its oldest line, newer than its newest: a line endoflife.date does not list yet is never refused)."""
    keys, names, newest = own_lines(product)
    if not keys:
        return True, ()
    vk = tuple(v.key)
    if any(vk[: len(k)] == k for k in keys):
        return True, ()
    depth = max(len(k) for k in keys)
    at = vk[:depth]
    lowest = min(keys)
    top = max([*keys, *([newest[:depth]] if newest else [])])
    if at < lowest[: len(at)] or at > top:
        return True, ()
    return False, tuple(names[:6])


def plausible(product: dict, value: str) -> tuple[bool, tuple[str, ...]]:
    scheme = product.get("scheme") or "generic"
    if scheme in NO_LINES or product.get("source") == "custom":
        return True, ()
    majors, names = known_majors(product)
    v = parse(scheme, value)
    if not majors or v is None or not v.key:
        return True, ()
    top = max(majors)
    major = v.key[0]
    if not (major in majors or major <= max(top * PLAUSIBLE_FACTOR, top + PLAUSIBLE_MARGIN)):
        return False, tuple(names)
    if product.get("lines_only"):
        return _on_own_line(product, v)
    return True, ()


# ---------------------------------------------------------------- the check


def _prepare(product: dict, t: str) -> str:
    """Steps 2 and 3: the product's name dropped ("iLO 6 v1.62" → "1.62"), its display-form rules applied."""
    scheme = product.get("scheme") or "generic"
    s = t
    if scheme not in ("vmware", "cloud"):
        s = strip_name(product, t)
        if s != t:
            s = re.sub(r"(?i)^(?:v(?=\d)|version\s*:?\s*)", "", s)
    for rule in product.get("normalize") or []:
        if (fn := NORMALIZE.get(rule)) is not None:
            s = _clean(fn(s))
    return s


def check(product: dict, text: str) -> Checked:
    """A typed version of a product: (ok, the value to store, reason, …) – see the module docstring."""
    t = _clean(text)
    scheme = product.get("scheme") or "generic"
    if not t:
        return Checked(False, "", "empty")
    if len(t) > INPUT_MAX:
        return Checked(False, t, "too_long")  # what is stored is at most MAX_LEN (validate) – a typed line may be longer
    for b in product.get("belongs") or []:
        if re.search(b["pattern"], t):
            return Checked(False, t, "other_product", to=b["to"])
    s = _prepare(product, t)
    key = str(product.get("key") or "")
    if scheme == "vmware":
        release, reason = vmware_builds.lookup(key, s)
    else:
        release, reason = build_maps.lookup_names(key, s)
    if reason:
        return Checked(False, t, reason, hint=build_maps.hint_of(key))
    ok, norm, reason = validate(scheme, release or s)
    if not ok:
        return Checked(False, t, reason, hint=product.get("pattern_hint") if reason == "format" else None)
    if (rx := product.get("pattern")) and not re.fullmatch(rx, norm, re.I):
        return Checked(False, t, "pattern", hint=product.get("pattern_hint"))
    good, lines = plausible(product, norm)
    if not good:
        return Checked(False, t, "implausible", hint=product.get("pattern_hint"), lines=lines)
    mapped = re.sub(r"[\s-]", "", norm.lower()) != re.sub(r"[\s-]", "", t.lower())
    return Checked(True, norm, "", mapped=mapped)


@lru_cache(maxsize=32768)
def _effective(scheme: str, rules_json: str, text: str) -> str | None:
    import json

    product = json.loads(rules_json)
    c = check(product, text)
    if c.ok:
        return c.value
    if c.reason in HARD:
        return None  # it means something else (another product, a build the tables do not know): not compared
    # "format": typed before the strict check (a word of its own before the number) – compared as it was read then,
    # after the product's name is dropped; the version card says "bitte prüfen"
    return _prepare(product, _clean(text))


RULE_FIELDS = ("key", "label", "vendor", "scheme", "eol", "source", "aliases", "kw", "belongs", "normalize", "pattern", "pattern_hint", "lines_only")


def effective(product: dict, text: str | None) -> str | None:
    """The version a stored text is compared as (see the module docstring); None: not compared ("möglicherweise
    betroffen"). Cached per product rules and text – the evaluation asks it for every advisory."""
    if not text:
        return text
    import json

    rules = {k: product.get(k) for k in RULE_FIELDS if product.get(k) is not None}
    blob = json.dumps(rules, sort_keys=True, default=str)
    return _effective(str(product.get("scheme") or "generic"), blob, text)


def clear() -> None:
    """The catalogue changed (release lines, rules): what was cached is computed again."""
    _effective.cache_clear()
    build_maps.clear()
