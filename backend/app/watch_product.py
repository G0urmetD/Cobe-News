"""The product of a watched CVE – what "Beobachtete CVEs" groups by (0.1.46, "Gruppieren nach: Produkt"). Worked out
anew on every read of the list from what is stored then: nothing is kept per watch, so an advisory linked hours after
the watch moves the CVE into its product's group with the next load. In this order:

1. **catalog** – the catalogue products the CVE's advisories are linked to (vendor_advisory_products, the links Vendor
   News uses). Several: a followed product first, then the one with the most advisories of the CVE, then by name. The
   label is the catalogue's of today (a merged or renamed key – catalogue `replaces` – counts as the product it is
   now); a product somebody added by CPE has the label it was given.
2. **cna** – the vendor and product the CNA names as affected in the CVE record (cvelistV5's copy first, else the NVD's),
   as given, "GitLab / GitLab" as "GitLab". A name that is exactly one catalogue product's (its label, its CNA names)
   is that product.
3. **nvd** – the vendor:product of the NVD's CPE configuration ("a:gitlab:gitlab"): a catalogue product with that CPE,
   else the names made readable ("microsoft:windows_server_2022" → "Microsoft Windows Server 2022").
4. **none** – nothing names a product ("Ohne Produktzuordnung").

The other products the same source names come as `others` (labels; the page: "+ N weitere Produkte"). A bounded
number of queries for any number of watched CVEs: the links of all their advisories, the followed products, the names
of the CVE records of those still without a product – each in chunks. Only the own database – nothing is fetched."""

import re
from collections import Counter

from sqlalchemy import func, literal_column, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app import vendor_catalog as catalog
from app.models import VendorAdvisory, VendorAdvisoryProduct, VendorFollow

CHUNK = 5000  # ids in one IN
OTHERS = 20  # other products named per CVE
LABEL_MAX = 120
SOURCES = ("catalog", "cna", "nvd", "none")
# CNA placeholders (MITRE's records say "n/a" for both)
NO_NAME = {"", "n/a", "na", "-", "unknown", "unspecified", "not applicable", "none", "*"}
_SPACE = re.compile(r"\s+")


def fold(text: str) -> str:
    """A name as it is grouped: trimmed, single spaces, case-insensitive."""
    return _SPACE.sub(" ", str(text or "")).strip().casefold()


def _clean(text: str) -> str:
    return _SPACE.sub(" ", str(text or "")).strip()


def cna_label(vendor: str, product: str) -> str | None:
    """"GitLab" / "GitLab" → "GitLab", "GitLab" / "GitLab CE/EE" → "GitLab CE/EE", "Microsoft" / "Windows" →
    "Microsoft Windows"; placeholders ("n/a") are no name. None: neither names anything."""
    v, p = _clean(vendor), _clean(product)
    v = "" if v.casefold() in NO_NAME else v
    p = "" if p.casefold() in NO_NAME else p
    if not p:
        return v[:LABEL_MAX] or None
    if not v or p.casefold().startswith(v.casefold()):
        return p[:LABEL_MAX]
    return f"{v} {p}"[:LABEL_MAX]


def _word(w: str) -> str:
    return w[:1].upper() + w[1:] if w.islower() else w


def cpe_names(criteria: str) -> tuple[str, str] | None:
    """(vendor, product) of a CPE 2.3 name – NVD's escapes undone ("cpe:2.3:a:gitlab:gitlab:*…" → gitlab, gitlab)."""
    parts = re.split(r"(?<!\\):", str(criteria or ""))
    if len(parts) < 5 or parts[0] != "cpe" or parts[3] in ("", "*", "-") or parts[4] in ("", "*", "-"):
        return None
    return parts[3].replace("\\", ""), parts[4].replace("\\", "")


def cpe_label(vendor: str, product: str) -> str:
    """"gitlab", "gitlab" → "Gitlab"; "microsoft", "windows_server_2022" → "Microsoft Windows Server 2022"."""
    v = " ".join(_word(w) for w in re.split(r"[_\s]+", vendor) if w)
    p = " ".join(_word(w) for w in re.split(r"[_\s]+", product) if w)
    if not p or p.casefold().startswith(v.casefold()):
        return (p or v)[:LABEL_MAX]
    return f"{v} {p}"[:LABEL_MAX]


# ---------------------------------------------------------------- the catalogue's names (once per catalogue)


class _Names:
    data: dict | None = None
    label: dict[str, set[str]] = {}
    cna: dict[tuple[str, str], set[str]] = {}
    cpe: dict[str, set[str]] = {}


_names = _Names()


def _cpe_key(cpe: str) -> str:
    """vendor:product of a catalogue CPE (part:vendor:product), as app/vendor.cpe_key."""
    return ":".join(re.split(r"(?<!\\):", cpe)[1:3]).replace("\\", "").casefold()


def _catalog_names() -> _Names:
    cat = catalog.load()
    if _names.data is not cat:
        label: dict[str, set[str]] = {}
        cna: dict[tuple[str, str], set[str]] = {}
        cpe: dict[str, set[str]] = {}
        for p in cat["products"]:
            k = p["key"]
            if p.get("label"):
                label.setdefault(fold(p["label"]), set()).add(k)
            for pair in p.get("cna") or []:
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    cna.setdefault((fold(pair[0]), fold(pair[1])), set()).add(k)
            for c in p.get("cpes") or []:
                cpe.setdefault(_cpe_key(str(c)), set()).add(k)
        _names.label, _names.cna, _names.cpe, _names.data = label, cna, cpe, cat
    return _names


def _one(keys: set[str] | None) -> str | None:
    """The product a name stands for – only when it is exactly one."""
    return next(iter(keys)) if keys and len(keys) == 1 else None


# ---------------------------------------------------------------- resolve


class _Products:
    """The followed products and the labels of today, read once per list."""

    def __init__(self, follows: list[tuple[str, bool, dict | None]]) -> None:
        self.followed: set[str] = set()
        self.custom: dict[str, str] = {}
        self.custom_cpe: dict[str, str] = {}
        for key, enabled, custom in follows:
            k = catalog.REPLACED.get(key, key)
            if custom:
                p = catalog.custom_product({**custom, "key": k})
                self.custom[k] = p["label"] or k
                for c in p["cpes"]:
                    self.custom_cpe[_cpe_key(c)] = k
            if enabled:
                self.followed.add(k)
        self.custom_label = {fold(lb): k for k, lb in self.custom.items()}

    def label(self, key: str) -> str | None:
        """The catalogue's label of today (None: a key neither the catalogue nor a custom product knows)."""
        if key in self.custom:
            return self.custom[key]
        p = catalog.product(key)
        return str(p["label"]) if p and p.get("label") else None

    def by_name(self, label: str, vendor: str = "", product: str = "") -> str | None:
        """The catalogue (or custom) product a CNA's or a CPE's name is: its label, or its CNA names – exactly one."""
        n = _catalog_names()
        f = fold(label)
        if f in self.custom_label:
            return self.custom_label[f]
        return _one(n.label.get(f)) or (_one(n.cna.get((fold(vendor), fold(product)))) if vendor or product else None)


def _out(key: str | None, label: str, source: str, others: list[str], followed: bool = False) -> dict:
    return {"key": key, "label": label, "source": source, "others": others[:OTHERS], "followed": followed}


def _pick(cands: list[tuple[str | None, str]], prods: _Products, source: str) -> dict:
    """The first named product (a catalogue one as such), the others as labels – each name once."""
    seen: dict[str, tuple[str | None, str]] = {}
    for key, label in cands:
        g = f"k:{key}" if key else f"n:{fold(label)}"
        seen.setdefault(g, (key, prods.label(key) or label if key else label))
    items = list(seen.values())
    key, label = items[0]
    return _out(key, label, source, [lb for _, lb in items[1:]], bool(key and key in prods.followed))


async def resolve(db: AsyncSession, advisories: dict[str, list[str]]) -> dict[str, dict]:
    """Per CVE (the keys of `advisories`: the ids of the advisories naming it, as cve_watch.facts finds them) its
    product: {key (catalogue key or None), label, source (catalog | cna | nvd | none), others (labels), followed}."""
    out: dict[str, dict] = {c: _out(None, "", "none", []) for c in advisories}
    ids = sorted({a for aids in advisories.values() for a in aids})
    if not ids:
        return out
    # 1. the catalogue products linked to the advisories
    links: dict[str, set[str]] = {}
    for i in range(0, len(ids), CHUNK):
        q = select(VendorAdvisoryProduct.product, VendorAdvisoryProduct.advisory_id).where(VendorAdvisoryProduct.advisory_id.in_(ids[i : i + CHUNK]))
        for key, aid in (await db.execute(q)).all():
            links.setdefault(aid, set()).add(catalog.REPLACED.get(key, key))
    prods = _Products([(k, bool(e), c) for k, e, c in (await db.execute(select(VendorFollow.product, VendorFollow.enabled, VendorFollow.custom))).all()])
    rest: list[str] = []
    for cve, aids in advisories.items():
        per: Counter[str] = Counter()
        for aid in set(aids):
            for key in links.get(aid, ()):
                per[key] += 1
        named = [(k, n, lb) for k, n in per.items() if (lb := prods.label(k))]
        if not named:
            rest.append(cve)
            continue
        named.sort(key=lambda x: (x[0] not in prods.followed, -x[1], fold(x[2]), x[0]))
        k0, _, lb0 = named[0]
        out[cve] = _out(k0, lb0, "catalog", [lb for _, _, lb in named[1:]], k0 in prods.followed)
    # 2. and 3. the names of the CVE records (cvelistV5, NVD) of the others – only the names are read
    want = {f"{src}:{c}": c for c in rest for src in ("cvelist", "nvd") if f"{src}:{c}" in set(advisories[c])}
    if not want:
        return out
    recs: dict[str, dict[str, tuple]] = {}

    def path(p: str):  # noqa: ANN202 - a constant path of this module, never a value of a request
        return func.jsonb_path_query_array(VendorAdvisory.data, literal_column(f"'{p}'::jsonpath"), type_=JSONB)

    keys = sorted(want)
    for i in range(0, len(keys), CHUNK):
        q = select(
            VendorAdvisory.id,
            VendorAdvisory.source,
            path("$.cna[*].affectedData[*].vendor"),
            path("$.cna[*].affectedData[*].product"),
            path("$.configs[*].nodes[*].cpeMatch[*].criteria"),
        ).where(VendorAdvisory.id.in_(keys[i : i + CHUNK]))
        for aid, source, vendors, products, criteria in (await db.execute(q)).all():
            recs.setdefault(want[aid], {})[source] = (vendors or [], products or [], criteria or [])
    for cve in rest:
        r = recs.get(cve)
        if not r:
            continue
        # the CNA's names – cvelistV5's record first, the NVD's copy of them else
        for source in ("cvelist", "nvd"):
            vendors, products, _ = r.get(source, ([], [], []))
            cands = []
            for v, p in zip(vendors, products, strict=False):
                if isinstance(v, str) and isinstance(p, str) and (lb := cna_label(v, p)):
                    cands.append((prods.by_name(lb, v, p), lb))
            if cands:
                out[cve] = _pick(cands, prods, "cna")
                break
        else:
            n = _catalog_names()
            cands = []
            for c in r.get("nvd", ([], [], []))[2]:
                if isinstance(c, str) and (vp := cpe_names(c)):
                    lb = cpe_label(*vp)
                    ck = f"{vp[0]}:{vp[1]}".casefold()
                    cands.append((prods.custom_cpe.get(ck) or _one(n.cpe.get(ck)) or prods.by_name(lb), lb))
            if cands:
                out[cve] = _pick(cands, prods, "nvd")
    return out
