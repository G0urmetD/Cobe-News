"""Build tables: what admins see (a build number, a cumulative update's name, an internal code) → the version advisories
compare. One file per table in catalog/build_maps/ (loaded and checked with the catalogue, app/catalog_data.py):

- ``kind: vmware``  vCenter Server and ESXi (Broadcom KB 326316 / 316595): four-part version and build → release. The
                    forms and the lookup are VMware's own (app/vmware_builds.py).
- ``kind: names``   any other product: a table of rows ``{value, names}`` – every name (``2019 CU15 Apr25HU``, ``KB5048033``,
                    a VMware Tools code ``12416``, a GlobalProtect build ``6.2.8-c948``) stands for the value that is
                    stored and compared (``15.2.1748.24``, ``16.0.4165.4``, ``12.4.0``, ``6.2.8-h10``). A name is
                    compared without case, punctuation and the product's own words (``strip``). ``extract`` takes a
                    version out of a longer text (SQL Server's ``SELECT @@VERSION``); a text of the form ``claims``
                    describes that the table does not know is refused (``unknown_name``) – never guessed.

`lookup(product_key, text)` → (value, reason) for both kinds: (None, "") when the table has nothing to say (the version
scheme decides as for every product).
"""

from __future__ import annotations

import re
from functools import lru_cache

# words and phrases written in more than one way (a name and the typed text are compared in this form)
_PHRASES = (
    (re.compile(r"cumulative\s+update"), "cu"),
    (re.compile(r"subscription\s+edition"), "se"),
    (re.compile(r"service\s+pack"), "sp"),
    (re.compile(r"\brtm\s*-\s*(?=cu\d)"), ""),  # SQL Server's "(RTM-CU16)"
)


def name_key(text: str, strip: tuple[str, ...] | list[str] = ()) -> str:
    """'Exchange Server 2019 Cumulative Update 15 Apr25HU' → '2019 cu15 apr25hu' (strip: exchange, server)."""
    t = (text or "").lower()
    for rx, repl in _PHRASES:
        t = rx.sub(repl, t)
    t = re.sub(r"[^a-z0-9.]+", " ", t)
    words = [w for w in t.split() if w not in strip]
    t = " ".join(words)
    return re.sub(r"\b([a-z]+) (?=\d)", r"\1", t)  # "cu 15" → "cu15", "kb 5048033" → "kb5048033"


@lru_cache(maxsize=1)
def _tables() -> dict[str, dict]:
    """Per product key the table of kind names: {"index": {name key: value}, "strip", "extract", "claims", "hint"}."""
    from app import vendor_catalog  # the catalogue data, loaded and checked once (catalog_data._build_maps)

    out: dict[str, dict] = {}
    for data in (vendor_catalog.DATA.build_maps or {}).values():
        if data.get("kind") != "names":
            continue
        strip = tuple(w.lower() for w in data.get("strip") or [])
        index = {name_key(n, strip): r["value"] for r in data["rows"] for n in r["names"]}
        table = {
            "index": index,
            "strip": strip,
            "extract": re.compile(data["extract"]) if data.get("extract") else None,
            "claims": re.compile(data["claims"]) if data.get("claims") else None,
            "hint": data.get("hint"),
        }
        for key in data["products"]:
            out[key] = table
    return out


def has_names(product_key: str) -> bool:
    return product_key in _tables()


def hint_of(product_key: str) -> str | None:
    """The texts.yaml hint shown when a typed name is not in the product's table."""
    t = _tables().get(product_key)
    return t["hint"] if t else None


def lookup_names(product_key: str, text: str) -> tuple[str | None, str]:
    """(value, reason) of a typed text in the product's table of names – (None, "") when it says nothing about it."""
    t = _tables().get(product_key)
    if t is None:
        return None, ""
    s = re.sub(r"\s+", " ", (text or "").strip())
    if t["extract"] is not None and (m := t["extract"].search(s)):
        return m.group(1), ""
    if (value := t["index"].get(name_key(s, t["strip"]))) is not None:
        return value, ""
    if t["claims"] is not None and t["claims"].search(s):
        return None, "unknown_name"
    return None, ""


def lookup(product_key: str, text: str) -> tuple[str | None, str]:
    """The value a typed text stands for in the product's build table (VMware's or a table of names)."""
    from app import vmware_builds

    if vmware_builds.has_table(product_key):
        return vmware_builds.lookup(product_key, text)
    return lookup_names(product_key, text)


def clear() -> None:
    _tables.cache_clear()
