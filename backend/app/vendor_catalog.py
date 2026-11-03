"""The Vendor News product catalogue: endoflife.date's product list (release lines, support and EOL dates, CPE
identifiers) plus the curated overlay (the data files in app/catalog/, loaded and checked by app/catalog_data.py).

Built from data, not written by hand: `build(eol)` takes endoflife.date's full dump (`/api/v1/products/full`, one
request) and returns the catalogue. A copy is bundled (app/data/vendor_catalog.json – `python -m app.vendor_catalog
<dump.json>` writes it); an admin's "Katalog aktualisieren" (and a daily refresh while products are followed) stores
a newer one in DATA_DIR/vendor_catalog.json – the newer of the two counts. Each copy keeps endoflife.date's part
(`eol_products`, `releases`) and the fingerprint of the overlay it was built with: a copy from another overlay (a refresh
before a rollout with new overlay entries) gets the current overlay applied on load. Products somebody added by CPE live
in the database (VendorFollow.custom) and are merged in by the caller.
"""

import hashlib
import json
import logging
import re
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

from app import catalog_data

# the curated data, checked at import (a broken file stops the start with file and product named – catalog_data.load)
DATA = catalog_data.load()
CATEGORIES: tuple[str, ...] = DATA.category_keys
OVERLAY: list[dict] = DATA.overlay
# keys merged into another product (`replaces`: db2 → ibm-db2 …) – an old link (/vendor?product=db2) opens the new one
REPLACED: dict[str, str] = {r: o["key"] for o in OVERLAY for r in o.get("replaces") or []}
CSAF_PROVIDERS: list[dict] = DATA.csaf  # catalog/csaf.yaml – the CSAF providers mapped to catalogue vendors

log = logging.getLogger("cobe_news.vendor")
BUNDLED = Path(__file__).resolve().parent / "data" / "vendor_catalog.json"
FORMAT = 2  # 2: the endoflife.date part (eol_products) and the overlay fingerprint are kept
CPE_SHORT = re.compile(r"^[aoh]:[^:\s]+:[^:\s]+$")
EOL_KEY = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}")  # an endoflife.date product key (fullmatch)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
RELEASE_FIELDS = ("name", "label", "releaseDate", "isLts", "isEol", "eolFrom", "eoasFrom", "isEoas", "isMaintained", "eoesFrom")
# endoflife.date's tags/categories → ours (first hit wins); the overlay says it for the products that matter most
TAG_CATEGORY = [
    ("linux-distribution", "os"),
    ("bsd-distribution", "os"),
    ("unix-distribution", "os"),
    ("database", "database"),
    ("web-browser", "client"),
    ("web-server", "web"),
    ("managed-kubernetes", "cloud"),
    ("kubernetes", "containers"),
]
# vendor tags only say something about servers and systems (Spring Boot carries "vmware" too)
SYSTEM_TAG_CATEGORY = [("vmware", "virtualization"), ("proxmox", "virtualization"), ("nutanix", "virtualization")]
EOL_CATEGORY = {"os": "os", "database": "database", "lang": "web", "framework": "dev", "service": "cloud", "device": "devices", "app": "client", "server-app": "other"}
SKIP_EOL_CATEGORIES = {"standard"}


def _cpe(short: str) -> str:
    return short if short.startswith("cpe:2.3:") else f"cpe:2.3:{short}"


def _cpe_short(cpe: str) -> str | None:
    """'cpe:2.3:o:fortinet:fortios' (or the 2.2 form 'cpe:/o:fortinet:fortios') → 'o:fortinet:fortios'. An escaped
    colon is part of its field (NVD's 'a:mailcow:mailcow\\:_dockerized')."""
    if cpe.startswith("cpe:2.3:"):
        parts = re.split(r"(?<!\\):", cpe[8:])
    elif cpe.startswith("cpe:/"):
        parts = re.split(r"(?<!\\):", cpe[5:])
    else:
        return None
    if len(parts) < 3 or not all(parts[:3]) or parts[0] not in ("a", "o", "h"):
        return None
    return ":".join(parts[:3])


def _category(p: dict) -> str:
    tags = p.get("tags") or []
    for tag, cat in TAG_CATEGORY:
        if tag in tags:
            return cat
    if p.get("category") in ("os", "server-app", "app"):
        for tag, cat in SYSTEM_TAG_CATEGORY:
            if tag in tags:
                return cat
    return EOL_CATEGORY.get(p.get("category") or "", "other")


def _releases(p: dict) -> list[dict]:
    out = []
    for r in p.get("releases") or []:
        if not isinstance(r, dict) or not isinstance(r.get("name"), str):
            continue
        row = {k: r.get(k) for k in RELEASE_FIELDS if r.get(k) is not None}
        latest = r.get("latest") if isinstance(r.get("latest"), dict) else {}
        if isinstance(latest.get("name"), str):
            row["latest"] = latest["name"][:64]
            if isinstance(latest.get("date"), str):
                row["latestDate"] = latest["date"][:10]
        out.append(row)
    return out[:200]


def _vendor_of(label: str, cpes: list[str]) -> str:
    if cpes:
        v = cpes[0].split(":")[1].replace("_", " ")
        return v[:1].upper() + v[1:]
    return label.split(" ")[0]


def catalog_version() -> str:
    """The version of the curated data (catalog.yaml, e.g. 2026.10.29-1) – separate from the app version."""
    return DATA.version


def fingerprint() -> str:
    """What the curated part looked like when a catalogue was built: a copy with another fingerprint gets the current
    overlay applied on load (a rollout with new overlay entries must not wait for the next endoflife.date refresh)."""
    blob = json.dumps({"format": FORMAT, "categories": list(CATEGORIES), "overlay": OVERLAY}, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def base(eol: dict | None) -> tuple[list[dict], dict[str, list[dict]]]:
    """endoflife.date's part of the catalogue, before the overlay: the products (compact – only what `_expand` cannot
    derive) and their release lines."""
    products: dict[str, dict] = {}
    releases: dict[str, list[dict]] = {}
    for p in (eol or {}).get("result") or []:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or p.get("category") in SKIP_EOL_CATEGORIES:
            continue
        if not EOL_KEY.fullmatch(p["name"]):
            # the key goes into links (notifications, /vendor?product=…) and markup: only what endoflife.date's keys
            # look like (security review 0.1.16 L6)
            log.warning("catalogue: endoflife.date product %r left out – not a valid key", p["name"][:80])
            continue
        key = p["name"]
        cpes = list(dict.fromkeys(c for i in p.get("identifiers") or [] if isinstance(i, dict) and i.get("type") == "cpe" and (c := _cpe_short(str(i.get("id") or "")))))
        row: dict = {"key": key, "category": _category(p)}
        label = str(p.get("label") or key)[:120]
        if label != key:
            row["label"] = label
        if cpes:
            row["cpes"] = cpes[:8]
        if aliases := [str(a)[:60] for a in (p.get("aliases") or [])][:8]:
            row["aliases"] = aliases
        if cmd := CONTROL.sub("", str(p.get("versionCommand") or ""))[:200].strip():
            row["version_cmd"] = cmd
        products[key] = row
        rel = _releases(p)
        if rel:
            releases[key] = rel
    return list(products.values()), releases


def _expand(row: dict) -> dict:
    """A compact endoflife.date product (from `base`) as a catalogue product."""
    key = str(row["key"])[:64]
    label = str(row.get("label") or key)[:120]
    cpes = [str(c) for c in row.get("cpes") or []][:8]
    return {
        "key": key,
        "label": label,
        "vendor": _vendor_of(label, cpes),
        "category": str(row.get("category") or "other"),
        "cpes": cpes,
        "eol": key,
        "scheme": "generic",
        "aliases": [str(a)[:60] for a in row.get("aliases") or []][:8],
        "source": "eol",
        "version_cmd": str(row.get("version_cmd") or "")[:200] or None,
        "version_cmd_from": "eol" if row.get("version_cmd") else None,  # shown as "laut endoflife.date"
    }


def build(eol: dict | None) -> dict:
    """The catalogue from endoflife.date's full dump (or None: the overlay alone) and the overlay."""
    eol_products, releases = base(eol)
    return apply_overlay(eol_products, releases, (eol or {}).get("generated_at"))


def apply_overlay(eol_products: list[dict], releases: dict[str, list[dict]], eol_generated_at: str | None, generated_at: str | None = None) -> dict:
    """The catalogue: endoflife.date's part (from `base`, or kept in an earlier catalogue) with the current overlay."""
    products: dict[str, dict] = {}
    for row in eol_products:
        p = _expand(row)
        products[p["key"]] = p
    for o in OVERLAY:
        key = o["key"]
        base = products.get(key)
        if o.get("label") is None:  # only a category / CPE / scheme for an endoflife.date product
            if base is None:
                continue  # not (any more) in endoflife.date – nothing to patch
            base["category"] = o["category"]
            base["cpes"] = list(dict.fromkeys([*base["cpes"], *(_cpe_short(_cpe(c)) or c for c in o.get("cpes", []))]))
            for k in ("scheme", "hint", "depth", "osv", "pattern", "pattern_hint", "normalize", "belongs", "cpe_editions", "replaces", "lines_only"):
                if o.get(k):
                    base[k] = o[k]
            if o.get("aliases"):
                base["aliases"] = list(dict.fromkeys([*o["aliases"], *(base.get("aliases") or [])]))[:12]
            continue
        entry = dict(base or {"key": key, "eol": None, "aliases": [], "source": "overlay", "version_cmd": None})
        own = [_cpe_short(_cpe(c)) or c for c in o.get("cpes", [])]
        entry |= {k: v for k, v in o.items() if k not in ("cpes",) and v is not None}
        if o.get("version_cmd"):
            entry["version_cmd_from"] = "catalog"
        entry["cpes"] = list(dict.fromkeys([*own, *((base or {}).get("cpes") or [])]))[:8]
        entry["aliases"] = list(dict.fromkeys([*(o.get("aliases") or []), *((base or {}).get("aliases") or [])]))[:12]
        if base is not None:
            entry["source"] = "eol+overlay"
        if "eol" in o:
            entry["eol"] = o["eol"]
        products[key] = entry
    for o in OVERLAY:  # duplicates merged into one product: the other key goes, its name stays findable
        keep = products.get(o["key"])
        for r in o.get("replaces") or []:
            gone = products.pop(r, None)
            if gone is not None and keep is not None and gone.get("label") and gone["label"] != keep.get("label"):
                keep["aliases"] = list(dict.fromkeys([*(keep.get("aliases") or []), gone["label"]]))[:12]
    for p in products.values():
        p.setdefault("scheme", "generic")
        p.setdefault("category", "other")
        if p["category"] not in CATEGORIES:
            p["category"] = "other"
        p["cpes"] = [c for c in p["cpes"] if CPE_SHORT.match(re.sub(r"\\.", "x", c))]
    counts: dict[str, int] = {}
    for p in products.values():
        counts[p["category"]] = counts.get(p["category"], 0) + 1
    return {
        "format": FORMAT,
        "generated_at": generated_at or datetime.now(UTC).replace(microsecond=0).isoformat(),
        "eol_generated_at": eol_generated_at,
        "overlay": fingerprint(),
        "counts": dict(sorted(counts.items())),
        "products": sorted(products.values(), key=lambda x: x["key"]),
        "releases": releases,
        "eol_products": sorted(eol_products, key=lambda x: x["key"]),
    }


# ---------------------------------------------------------------- loading


class _Cache:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.data: dict | None = None
        self.by_key: dict[str, dict] = {}
        self.stamp: tuple = ()


_cache = _Cache()


def _data_file() -> Path:
    from app.config import get_config

    return get_config().data_dir / "vendor_catalog.json"


def _read(path: Path) -> dict | None:
    try:
        d = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and d.get("format") == FORMAT and isinstance(d.get("products"), list) else None


def _current(d: dict, fp: str) -> dict | None:
    """A stored catalogue as it is when it was built from this overlay, else with the current overlay applied again
    (from the endoflife.date part it keeps); None when that is missing or broken."""
    if d.get("overlay") == fp:
        return d
    rows, rel = d.get("eol_products"), d.get("releases")
    if not isinstance(rows, list) or not isinstance(rel, dict) or not all(isinstance(r, dict) and isinstance(r.get("key"), str) for r in rows):
        return None
    try:
        return apply_overlay(rows, rel, d.get("eol_generated_at"), str(d.get("generated_at") or "") or None)
    except Exception:  # noqa: BLE001 - a damaged copy is skipped, never the end of the catalogue
        log.warning("vendor catalogue: could not apply the overlay to a stored copy", exc_info=True)
        return None


def load() -> dict:
    """The catalogue in use: the refreshed copy in DATA_DIR if it is newer than the bundled one – with the current
    overlay (a copy built from another one gets it applied again, once per change of the files)."""
    paths = [BUNDLED, _data_file()]
    stamp = tuple(p.stat().st_mtime if p.is_file() else 0 for p in paths)
    with _cache.lock:
        if _cache.data is not None and _cache.stamp == stamp:
            return _cache.data
        fp = fingerprint()
        copies = [d for p in paths if p.is_file() and (d := _read(p))]
        # the newest first; on a tie the bundled one (listed first)
        copies.sort(key=lambda d: str(d.get("generated_at") or ""), reverse=True)
        best = next((c for d in copies if (c := _current(d, fp)) is not None), None) or build(None)
        _cache.data, _cache.stamp = best, stamp
        _cache.by_key = {p["key"]: p for p in best["products"]}
        _depths.clear()
        from app import version_input  # what was read with the old release lines (plausibility) is read again

        version_input.clear()
        return best


_depths: dict[str, int] = {}


def want_depth(product: dict) -> int | None:
    """How many parts a complete version of the product has – the catalogue's `depth`, else what its release lines
    show. None: nothing says so (no release data) – then no version counts as short ("ungenau")."""
    if product.get("depth"):
        return int(product["depth"])
    return depth(product.get("eol")) or None


def depth(eol_key: str | None) -> int:
    """full_depth of a product's release lines (cached until the catalogue changes); 0: unknown."""
    if not eol_key:
        return 0
    d = _depths.get(eol_key)
    if d is None:
        d = _depths[eol_key] = full_depth(releases(eol_key))
    return d


def full_depth(rels: list[dict]) -> int:
    """How many parts a complete version of a product has: the deepest latest release of its newest lines (PostgreSQL 17.2 → 2,
    nginx 1.27.3 → 3, Chrome 131.0.6778.85 → 4); 0 without release lines (unknown). A version with fewer parts ("1.25" for nginx)
    stands for several releases – the matching decides only what holds for all of them (vendor_match.evaluate)."""
    if not rels:
        return 0
    depths = [lead_depth(str(r.get("latest") or "")) for r in rels[:3]]
    depths = [d for d in depths if d]
    # the shallowest of the newest lines: a hotfix release (Notepad++ 8.9.8.1, Java 27.0.1.0.3) does not make the
    # normal three-part releases "ungenau"; a suffix (SQL Server "CU27+GDR", GlobalProtect "-c1084") is no part
    return max(2, min(min(depths), 6)) if depths else 3  # lines without their latest release: three parts as a rule


LEAD = re.compile(r"^\s*[vV]?(\d+(?:\.\d+)*)")


def lead_depth(text: str) -> int:
    """How many numeric parts a version starts with ("16.0.4305.5 CU27+GDR" → 4, "6.3.3-c1199" → 3, "" → 0)."""
    m = LEAD.match(text or "")
    return m.group(1).count(".") + 1 if m else 0


def lead(text: str) -> str | None:
    """The numeric start of a version ("16.0.4305.5 CU27+GDR" → "16.0.4305.5")."""
    m = LEAD.match(text or "")
    return m.group(1) if m else None


def product(key: str) -> dict | None:
    load()
    return _cache.by_key.get(key)


def releases(key: str | None) -> list[dict]:
    if not key:
        return []
    return list(load().get("releases", {}).get(key) or [])


def save_refreshed(cat: dict) -> None:
    """A catalogue built from a fresh endoflife.date dump – written next to the database (0600, atomically)."""
    import os

    path = _data_file()
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cat, f, separators=(",", ":"))
    tmp.replace(path)
    with _cache.lock:
        _cache.stamp = ()


def custom_product(custom: dict) -> dict:
    """A product somebody added by CPE (not in the catalogue): what the matching needs."""
    cpe = _cpe_short(_cpe(str(custom.get("cpe") or ""))) or ""
    return {
        "key": str(custom.get("key") or ""),
        "label": str(custom.get("label") or cpe)[:120],
        "vendor": str(custom.get("vendor") or _vendor_of("", [cpe] if cpe else []))[:80],
        "category": custom.get("category") if custom.get("category") in CATEGORIES else "other",
        "cpes": [cpe] if cpe else [],
        "eol": None,
        "scheme": "generic",
        "aliases": [],
        "source": "custom",
        "kw": [str(custom.get("label") or "")[:80]] if custom.get("label") else [],
    }


if __name__ == "__main__":  # python -m app.vendor_catalog <endoflife full dump> – rewrites the bundled catalogue
    src = json.loads(Path(sys.argv[1]).read_text())
    cat = build(src)
    BUNDLED.parent.mkdir(parents=True, exist_ok=True)
    BUNDLED.write_text(json.dumps(cat, separators=(",", ":"), ensure_ascii=False))
    print(f"{len(cat['products'])} products, {len(cat['releases'])} with release lines -> {BUNDLED}", cat["counts"])
