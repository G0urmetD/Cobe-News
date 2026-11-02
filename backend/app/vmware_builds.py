"""vCenter Server and ESXi: the version forms admins actually see, looked up as the release the vmware scheme compares.

vCenter shows a four-part version (VAMI → Summary, vSphere Client → About: ``8.0.3.00400``) and a build
(``24322831``); ESXi shows ``8.0.3, 24022510`` (host client) or ``VMware ESXi 8.0.3 build-24022510`` (``vmware -v``).
Advisories name releases (``8.0 U3d``), so such a form is looked up in Broadcom's tables (catalog/vmware_builds.yaml,
one per product – vCenter's and ESXi's builds are different numbers) and stored as the release. The four-part suffixes
follow no formula: an unknown version or build is refused with a hint, never guessed.

From vSphere 9 on the four-part version is the release itself (9.0.2.0100) – it is left to the scheme as it is.
"""

import re
from functools import lru_cache

from app.vendor_versions import VMW_FOUR_FROM, parse

PRODUCTS = ("vcenter", "esxi")

# texts of the 422 for API callers (the UI has its own, vendor.invalid.<reason>)
HINTS = {
    "unknown_build": {
        "de": "Unbekannter Build bzw. unbekannte Version – trage die Version als 8.0 U3d ein (vCenter: VAMI → Übersicht; welcher Release ein Build ist, steht in Broadcom KB 326316 für vCenter und KB 316595 für ESXi).",
        "en": "Unknown build or version – enter the version as 8.0 U3d (vCenter: VAMI → Summary; which release a build is, Broadcom KB 326316 says for vCenter and KB 316595 for ESXi).",
    },
    "build_mismatch": {
        "de": "Version und Build passen nicht zusammen – bitte die Angaben prüfen oder nur den Build eintragen.",
        "en": "Version and build do not belong together – please check them or enter the build alone.",
    },
}

_PREFIX = re.compile(r"^(?:vmware\s+)?(?:vcenter(?:\s+server)?(?:\s+appliance)?|vcsa|esxi|vsphere(?:\s+client)?)\b[\s,:]*", re.I)
_VERSION_WORD = re.compile(r"^(?:version|ver\.?|v(?=\d))\s*:?\s*", re.I)
_FOUR = re.compile(r"^(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{1,5})$")
# "24322831", "build-24022510", "8.0.3-24022510", "8.0.3, 24022510", "8.0.3 build-24022510", "8.0.3.00400 Build 24322831",
# "8.0 U3 (build 24022510)", "Version: 8.0.3, Build: 24022510"
_BUILD = re.compile(
    r"^(?:(?P<ver>\d{1,2}\.\d{1,2}(?:\.\d{1,5}){0,2}[a-z]?(?:\s*(?:u|update)\s*\d{1,2}\s*[a-z]?)?)\s*(?:[,;]\s*|-\s*|\s+|(?=\())?)?"
    r"(?:\(?\s*build\s*(?:number)?\s*[-:#]?\s*)?(?P<build>\d{6,9})\s*\)?$",
    re.I,
)


@lru_cache(maxsize=1)
def tables() -> dict[str, tuple[dict[str, str], dict[int, str], dict[int, str], set[int]]]:
    """Per product: four-part version → release, build → release, build → four-part version, the majors the table knows."""
    from app import vendor_catalog  # the catalogue data, loaded and checked once (catalog_data._vmware_builds)

    raw = vendor_catalog.DATA.vmware_builds or {}
    out = {}
    for product in PRODUCTS:
        rows = raw.get(product) or []
        by_version = {r["version"]: r["release"] for r in rows if r.get("version")}
        by_build = {int(r["build"]): r["release"] for r in rows}
        version_of = {int(r["build"]): r["version"] for r in rows if r.get("version")}
        majors = {int(r["release"].split(".")[0]) for r in rows}
        out[product] = (by_version, by_build, version_of, majors)
    return out


def has_table(product_key: str) -> bool:
    return product_key in PRODUCTS and bool(tables()[product_key][1])


def lookup(product_key: str, text: str) -> tuple[str | None, str]:
    """(release, reason) of a typed version of vCenter or ESXi:

    - ``(None, "")``             not a four-part version or a build – the scheme decides as for every product
    - ``("8.0 U3d", "")``        found in the product's table
    - ``(None, "unknown_build")`` a four-part version (before 9.0) or a build the table does not know
    - ``(None, "build_mismatch")`` version and build given, but the build belongs to another release
    - ``("9.0.2.0100", "")``     a version from 9.0 on with a build: the version (no table needed)
    """
    if not has_table(product_key):
        return None, ""
    by_version, by_build, version_of, majors = tables()[product_key]
    t = re.sub(r"\s+", " ", (text or "").strip())
    t = _VERSION_WORD.sub("", _PREFIX.sub("", t))
    if m := _FOUR.match(t):
        if int(m.group(1)) >= VMW_FOUR_FROM:
            return None, ""  # vSphere 9: the four-part version is the release
        return (by_version[_four(m)], "") if _four(m) in by_version else (None, "unknown_build")
    m = _BUILD.match(t)
    if not m:
        return None, ""
    ver = m.group("ver")
    if ver and int(ver.split(".")[0]) not in majors and int(ver.split(".")[0]) >= VMW_FOUR_FROM and parse("vmware", ver.strip()) is not None:
        return ver.strip(), ""  # vSphere 9 (no table): its version is the release – the build next to it is left out
    release = by_build.get(int(m.group("build")))
    if release is None:
        return None, "unknown_build"
    if ver and not _same_release(ver, release, version_of.get(int(m.group("build")))):
        return None, "build_mismatch"
    return release, ""


def _four(m: re.Match) -> str:
    """8.0.3.400 → 8.0.3.00400 (the table writes five digits)."""
    a, b, c, d = m.groups()
    return f"{int(a)}.{int(b)}.{int(c)}.{int(d):05d}"


def _same_release(ver: str, release: str, four: str | None) -> bool:
    """Whether the version written next to a build fits the build's release: 8.0 / 8.0.3 / 8.0 U3 / 8.0 U3d /
    8.0.3.00400 for 8.0 U3d (vmware -l says "8.0 Update 3" for every patch of U3)."""
    ver = ver.strip()
    if (m := _FOUR.match(ver)) is not None:
        return four is not None and _four(m) == four
    v, r = parse("vmware", ver), parse("vmware", release)
    if v is None or r is None:
        return False
    if len(v.key) >= 4:
        return v == r  # the letter is said ("8.0 U3d build …"): it must be the build's
    n = 2 if re.fullmatch(r"\d+\.\d+", ver) else 3  # "8.0": the line; "8.0.3", "8.0 U3": the update
    return (r.key + (0,) * 4)[:n] == (v.key + (0,) * 4)[:n]
