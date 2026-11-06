"""The curated part of the Vendor News catalogue, as data (backend/app/catalog/) – loaded and checked here.

Layout (docs/BETRIEB.md „Katalog pflegen“):

    catalog/catalog.yaml           catalog_version (date-based, e.g. 2026.10.29-1) and the data format
    catalog/categories.yaml        the categories in display order: key, icon (lucide name), label in de and en
    catalog/texts.yaml             hints shown with a product and "where is the version" texts, in de and en
    catalog/products/<cat>.yaml    the products of one category (file name = category), in the order they are kept
    catalog/csaf.yaml              the CSAF 2.0 providers Vendor News reads, each mapped to catalogue vendors
                                   (app/csaf_providers.py)
    catalog/cnas.yaml              CNAs (who wrote a CVE record) and the catalogue vendors they are – the CNA's
                                   affected data is the vendor's own word only then (app/vendor_match.cna_by)
    catalog/build_maps/<name>.yaml build tables: what admins see → the version advisories compare (app/build_maps.py):
                                   vmware.yaml (vCenter/ESXi, Broadcom KB 326316 / 316595 – app/vmware_builds.py),
                                   exchange.yaml, sqlserver.yaml, vmware_tools.yaml, globalprotect.yaml (tables of names)
    catalog/schema/*.schema.json   JSON Schema of these files for editors – generated from the models below
                                   (`python -m app.catalog_data --write-schema`; a test checks they are current)

A product entry on top of endoflife.date's product list: display name, vendor, CPEs ("part:vendor:product" of the NVD CPE
dictionary), the version scheme (app/vendor_versions.py), the vendor's own advisory source (adv), the names products
have in vendor advisories (names) and in the CNA data of CVE records (cna), words that find related news (kw), a hint, …
An entry whose key is an endoflife.date product patches that product (its CPEs are added to the ones endoflife.date
names); an entry without a label only moves such a product into its category (and may add CPEs, a scheme or a hint).

Everything is checked when the app starts (and in the tests): the schema of each file, unique keys over all files, known
categories, CPEs in the short form, known schemes and advisory sources, and that every hint, "where" text and category has
a German and an English text. A broken file stops the start with a message that names file and product – the catalogue
ships with the image, so this is caught by the tests before a release.

`load()` returns what the rest of the code used to import from the Python overlay: CATEGORIES (ordered keys) and OVERLAY
(one dict per entry, with "category" from the file name, the same fields the old P(...) rows had).

Later: a signed catalogue update (not built yet – docs/BETRIEB.md „Katalog pflegen“ → „Signierte Katalog-Updates (geplant)“) would
deliver this same directory layout as a bundle, checked with `load(path)` before it is used.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from app.vendor_versions import SCHEMES

DIR = Path(__file__).resolve().parent / "catalog"
FORMAT = 1  # the layout of these files; a catalogue of another format is refused
ADVISORY_SOURCES = ("paloalto", "fortinet", "veeam")  # app/vendor_sources.py; CSAF providers: csaf.yaml (by vendor)
# OSV ecosystems (osv.dev) a product may name its packages in – the ones with ECOSYSTEM/SEMVER version ranges
OSV_ECOSYSTEMS = ("Go", "Maven", "npm", "NuGet", "Packagist", "PyPI", "RubyGems", "crates.io", "Hex", "Pub", "Bitnami")
ICONS = (
    "activity", "app-window", "archive-restore", "brick-wall", "briefcase", "cloud", "code", "container", "database",
    "factory", "file-badge", "globe", "hard-drive", "key-round", "laptop", "layers", "lock-keyhole", "mail",
    "monitor-smartphone", "network", "package", "printer", "scan-search", "scroll-text", "server", "shield", "split",
    "terminal", "ticket", "users",
)  # frontend/src/lib/catalog-icons.tsx maps these names – a new icon needs an entry there
KEY = r"^[a-z0-9][a-z0-9._-]{1,63}$"
CPE = r"^[aoh]:(?:[^:\s*?\\]|\\.)+:(?:[^:\s*?\\]|\\.)+$"  # part:vendor:product, NVD escapes (\& \!) allowed, no wildcards
VERSION = r"^\d{4}\.\d{2}\.\d{2}-\d{1,3}$"

Text = Annotated[str, StringConstraints(min_length=1, max_length=200, strip_whitespace=False)]
LongText = Annotated[str, StringConstraints(min_length=1, max_length=2000)]
Key = Annotated[str, StringConstraints(pattern=KEY)]
Cpe = Annotated[str, StringConstraints(pattern=CPE, max_length=200)]
TextKey = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,40}$")]


class _Strict(BaseModel):
    # strict: a YAML value that is not a string (8.0, yes, off) is an error, not silently converted
    model_config = ConfigDict(extra="forbid", strict=True)


# app/version_input.py: product rules for typed versions (a display form → the form advisories use)
NORMALIZERS = ("two_digit_year", "netscaler", "ise_patch", "office_build", "nginx_plus", "checkpoint", "horizon_yymm", "leading_zeros", "ipfire_core")
Regex = Annotated[str, StringConstraints(min_length=1, max_length=300)]


class Belongs(_Strict):
    """A typed version of this form is another product's (pfSense Plus 24.11 typed for pfSense CE)."""

    pattern: Regex = Field(description="Regular expression (Python, searched) on the typed version.")
    to: Annotated[str, StringConstraints(pattern=KEY)] = Field(description="Key of the product it belongs to.")


class Edition(_Strict):
    """One edition of a product whose editions share version numbers (SharePoint 2016/2019/SE are all 16.0.x): a CVE
    record's row for an edition – its product name contains all words of `name` – only speaks for builds in its range."""

    name: Text = Field(description="Words of the edition in CNA product names, e.g. '2019' or 'Subscription Edition'.")
    start: Text = Field(alias="from", description="First build of the edition, e.g. 16.0.10000.")
    below: Text | None = Field(None, description="First build after the edition (none: open).")
    cpe: Text | None = Field(None, description="The edition in NVD's CPE (version or sw_edition field), e.g. 2019 or subscription.")


class Product(_Strict):
    """One product of the catalogue (or, without label, a patch of an endoflife.date product)."""

    key: Key = Field(description="Unique over all files; for an endoflife.date product its key there (e.g. 'nginx').")
    label: Text | None = Field(None, description="Display name. Without a label the entry only patches the endoflife.date product of this key.")
    vendor: Text | None = Field(None, description="Vendor shown with the product (required with a label).")
    cpes: list[Cpe] = Field([], max_length=8, description="NVD CPE short form part:vendor:product, e.g. o:fortinet:fortios.")
    eol: Key | None = Field(None, description="endoflife.date key for release lines and support dates, if it differs from key.")
    scheme: Literal[SCHEMES] | None = Field(None, description="Version scheme (app/vendor_versions.py); default generic.")  # type: ignore[valid-type]
    adv: Literal[ADVISORY_SOURCES] | None = Field(None, description="The vendor's structured advisories.")  # type: ignore[valid-type]
    cloud: bool | None = Field(None, description="A service without a version on the customer side (scheme must be cloud).")
    names: list[Text] | None = Field(None, description="Product names in the vendor's advisories.")
    cna: list[Annotated[list[Text], Field(min_length=2, max_length=2)]] | None = Field(None, description="[vendor, product] in the CNA data of CVE records.")
    kw: list[Text] | None = Field(None, description="Words that find related news.")
    aliases: list[Text] | None = Field(None, description="Other names the catalogue search finds.")
    example: Text | None = Field(None, description="An example version, shown as placeholder.")
    depth: int | None = Field(None, ge=1, le=8, description="Parts of a complete version where endoflife.date has none or odd ones (fewer: 'ungenau').")
    version_cmd: Text | None = Field(None, description="Command (or place) that shows the version.")
    where: TextKey | None = Field(None, description="Key of a text in texts.yaml (where) – where the version is read.")
    hint: TextKey | None = Field(None, description="Key of a text in texts.yaml (hints) shown with the product.")
    filter: Text | None = Field(
        None, description="A word a CVE must mention (Hyper-V shares the Windows CPEs); several alternatives separated by | (one of them must be mentioned)."
    )
    replaces: list[Key] | None = Field(
        None,
        max_length=8,
        description="Keys this product replaces (duplicates merged into it): an endoflife.date product of such a key is left out, its name found as an alias; follows were moved by a migration.",
    )
    osv: list[Annotated[list[Text], Field(min_length=2, max_length=2)]] | None = Field(
        None, max_length=8, description="[ecosystem, package] in OSV (osv.dev) – an open-source product whose fixed versions OSV adds (by CVE id only)."
    )
    pattern: Regex | None = Field(None, description="Regular expression (Python, whole text, no case) a stored version must match – e.g. Exchange builds only.")
    pattern_hint: TextKey | None = Field(None, description="Key of a text in texts.yaml (hints) shown when a version does not match `pattern`.")
    normalize: list[Literal[NORMALIZERS]] | None = Field(None, description="Rules that turn display forms into the compared form (app/version_input.py).")  # type: ignore[valid-type]
    belongs: list[Belongs] | None = Field(None, max_length=4, description="Typed versions of another product's form (split products).")
    editions: list[Edition] | None = Field(None, max_length=12, description="Editions sharing version numbers – a record's row for one edition decides only for its builds.")
    line_depth: int | None = Field(None, ge=2, le=6, description="Parts that name a line with its own rows in CVE records (Exchange: 15.2.1748 = 2019 CU15).")
    excluded_names: list[Text] | None = Field(
        None,
        max_length=8,
        description="Product names in advisories (CSAF entries, CNA rows) that are another product although CPE or name match – Dovecot: 'OX Dovecot Pro' (Open-Xchange's commercial line, same CPE).",
    )
    lines_only: Literal["lts", "all"] | None = Field(
        None,
        description="Only some release lines are the product's (Firefox ESR, Jenkins LTS: 'lts' – the lines endoflife.date marks LTS; 'all': every listed line): a typed version between them on none of them is refused.",
    )
    cpe_editions: list[Annotated[list[Text], Field(min_length=2, max_length=2)]] | None = Field(
        None, max_length=8, description="[cpe, sw_edition]: only NVD CPE matches of these editions count for that CPE (Firefox '-' vs 'esr', Jenkins 'lts')."
    )


class Category(_Strict):
    key: TextKey
    icon: Literal[ICONS]  # type: ignore[valid-type]
    de: Text
    en: Text


class CategoriesFile(_Strict):
    categories: list[Category] = Field(min_length=1)


class I18nText(_Strict):
    de: LongText
    en: LongText


class TextsFile(_Strict):
    hints: dict[TextKey, I18nText]
    where: dict[TextKey, I18nText]


class CatalogFile(_Strict):
    catalog_version: Annotated[str, StringConstraints(pattern=VERSION)] = Field(description="Date-based, e.g. 2026.10.29-1; raise with every change.")
    format: Literal[1]


class ProductsFile(BaseModel):
    """A list of products (the root of products/<category>.yaml)."""

    model_config = ConfigDict(extra="forbid", strict=True)
    products: list[Product]


HOST = r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://[a-z0-9.-]+(?::\d{2,5})?/[^\s]{0,300}$", max_length=320)]


class CsafProvider(_Strict):
    """A CSAF 2.0 provider (its provider-metadata.json) and the catalogue vendors whose products its advisories are about."""

    key: TextKey = Field(description="Unique, short (siemens, cisco …) – the health page shows it (csaf:<key>).")
    name: Text = Field(description="Shown name, e.g. 'Siemens ProductCERT'.")
    domain: Annotated[str, StringConstraints(pattern=HOST, max_length=200)] = Field(
        description="The provider's host: its provider-metadata.json is looked up in the BSI aggregator by this host, else at https://<domain>/.well-known/csaf/provider-metadata.json."
    )
    metadata: HttpsUrl | None = Field(None, description="The provider-metadata.json address, when it is neither in the aggregator nor at the well-known place.")
    vendors: list[Text] = Field(min_length=1, max_length=10, description="Catalogue vendors (as in the products' vendor field) the provider speaks for.")
    hosts: list[Annotated[str, StringConstraints(pattern=HOST, max_length=200)]] | None = Field(
        None, max_length=5, description="Hosts (or their parent domains) feeds and documents may come from; default: the domain's last two labels."
    )


class CsafFile(_Strict):
    providers: list[CsafProvider] = Field(max_length=100)


# a CNA as a CVE record names it: cvelistV5's short name (palo_alto, GitHub_M, @huntr_ai), the NVD's sourceIdentifier
# (an address or the CNA's UUID), or "*@<domain>" – every address at that domain
CnaId = Annotated[str, StringConstraints(pattern=r"^(?:@?[A-Za-z0-9][A-Za-z0-9_.-]{0,59}|(?:\*|[A-Za-z0-9._%+-]{1,64})@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$", max_length=260)]


class Cna(_Strict):
    """A CNA (CVE Numbering Authority) and the catalogue vendors it is – its CVE records count as their own word."""

    key: TextKey = Field(description="Unique, short (github, vuldb …).")
    name: Text = Field(description="Shown name, e.g. 'GitHub' – „laut GitHub (nicht der Hersteller)“.")
    ids: list[CnaId] = Field(
        min_length=1,
        max_length=20,
        description="How CVE records name it: cvelistV5 short name (assignerShortName, e.g. GitHub_M), NVD sourceIdentifier (address or UUID), or *@<domain> for every address there. Compared without case.",
    )
    vendors: list[Text] = Field(
        [],
        max_length=10,
        description="Catalogue vendors (as in the products' vendor field) the CNA is – for their products its affected data is the vendor's own word. Empty: a third party for every product (VulDB, MITRE …).",
    )


class CnaFile(_Strict):
    cnas: list[Cna] = Field(max_length=500)


Day = Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}$")]
Source = Annotated[str, StringConstraints(min_length=8, max_length=300)]
Release = Annotated[str, StringConstraints(pattern=r"^\d{1,2}\.\d{1,2}(?:\.0)?[a-z]?(?: U\d{1,2}[a-z]?)?$", max_length=20)]


class VcenterBuild(_Strict):
    release: Release = Field(description="The release as the vmware scheme writes it: 8.0 U3d, 8.0c, 7.0.0d, 8.0 (GA).")
    version: Annotated[str, StringConstraints(pattern=r"^\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{5}$")] = Field(description="vCenter's four-part version (VAMI → Summary), e.g. 8.0.3.00400.")
    build: int = Field(ge=100000, le=999999999, description="The build number, e.g. 24322831.")
    date: Day


class EsxiBuild(_Strict):
    release: Release = Field(description="The release as the vmware scheme writes it: 8.0 U3e, 8.0c, 8.0 (GA).")
    build: int = Field(ge=100000, le=999999999, description="The build number, e.g. 24022510.")
    date: Day


class VmwareBuildsFile(_Strict):
    """build_maps/vmware.yaml: vCenter Server and ESXi release per four-part version and build (Broadcom KB 326316 and
    KB 316595)."""

    kind: Literal["vmware"]
    fetched: Day = Field(description="When the tables were taken from the KB articles.")
    sources: list[Source] = Field(min_length=1, max_length=10, description="Where the tables come from.")
    vcenter: list[VcenterBuild] = Field(min_length=1, max_length=2000)
    esxi: list[EsxiBuild] = Field(min_length=1, max_length=2000)


class NameRow(_Strict):
    value: Annotated[str, StringConstraints(min_length=1, max_length=40)] = Field(description="What is stored and compared, in the product's version scheme.")
    names: list[Annotated[str, StringConstraints(min_length=1, max_length=80)]] = Field(min_length=1, max_length=8, description="What admins see or type for it.")
    date: Day | None = None


class NamesMapFile(_Strict):
    """build_maps/<name>.yaml of kind names: typed names → the value compared (Exchange CU/SU → build …)."""

    kind: Literal["names"]
    fetched: Day = Field(description="When the table was taken from its sources.")
    sources: list[Source] = Field(min_length=1, max_length=10, description="Where the table comes from (official pages).")
    products: list[Annotated[str, StringConstraints(pattern=KEY)]] = Field(min_length=1, max_length=8, description="The catalogue products it is for.")
    strip: list[Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{1,30}$")]] = Field([], max_length=12, description="Words dropped before a name is looked up (the product's own name).")
    extract: Regex | None = Field(None, description="Regular expression with one group: a version inside a longer text, taken as it is.")
    claims: Regex | None = Field(None, description="Regular expression: a text of this form must be in the table – else it is refused (unknown_name).")
    hint: TextKey | None = Field(None, description="Key of a text in texts.yaml (hints) shown when a name is not in the table.")
    rows: list[NameRow] = Field(min_length=1, max_length=3000)


BUILD_MAP_KINDS = {"vmware": VmwareBuildsFile, "names": NamesMapFile}
SCHEMA_FILES = {
    "catalog": CatalogFile,
    "categories": CategoriesFile,
    "texts": TextsFile,
    "csaf": CsafFile,
    "cnas": CnaFile,
    "build_map_vmware": VmwareBuildsFile,
    "build_map_names": NamesMapFile,
}


class CatalogError(ValueError):
    """The catalogue data is broken: the message names the file (and product)."""


@dataclass
class Catalog:
    version: str
    categories: list[dict]  # {"key", "icon", "de", "en"} in display order
    texts: dict[str, dict[str, dict[str, str]]]  # {"hints": {key: {de, en}}, "where": {...}}
    overlay: list[dict] = field(default_factory=list)  # one dict per product entry (see the module docstring)
    csaf: list[dict] = field(default_factory=list)  # the CSAF providers (csaf.yaml), in file order
    cnas: list[dict] = field(default_factory=list)  # the CNAs mapped to catalogue vendors (cnas.yaml), in file order
    build_maps: dict = field(default_factory=dict)  # build_maps/<name>.yaml by name: {"kind", "fetched", "sources", …}

    @property
    def category_keys(self) -> tuple[str, ...]:
        return tuple(c["key"] for c in self.categories)

    @property
    def vmware_builds(self) -> dict:
        """build_maps/vmware.yaml: {"kind", "fetched", "sources", "vcenter": [...], "esxi": [...]}."""
        return self.build_maps.get("vmware") or {}


def _yaml(path: Path, d: Path):
    name = path.relative_to(d).as_posix()
    try:
        return yaml.load(path.read_text(encoding="utf-8"), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))  # noqa: S506 - safe loader
    except OSError as e:
        raise CatalogError(f"{name}: cannot be read ({e.strerror})") from e
    except yaml.YAMLError as e:
        raise CatalogError(f"{name}: not valid YAML – {e}") from e


def _why(e: ValidationError, data, root: str = "") -> str:
    """The first problems of a validation error, readable: 'product 'fortios' (entry 3): cpes.0: String should match …'."""
    out = []
    for err in e.errors()[:3]:
        loc = list(err["loc"])
        where = ""
        if root == "products" and len(loc) >= 2 and loc[0] == "products" and isinstance(loc[1], int):
            entry = data["products"][loc[1]] if isinstance(data, dict) else None
            key = entry.get("key") if isinstance(entry, dict) else None
            where = f"product {key!r} (entry {loc[1] + 1})" if key else f"entry {loc[1] + 1}"
            loc = loc[2:]
        field_ = ".".join(str(x) for x in loc)
        out.append(f"{where}{': ' if where and field_ else ''}{field_}: {err['msg']}" if field_ or where else err["msg"])
    return "; ".join(out)


def _check(model: type[BaseModel], data, name: str, root: str = ""):
    try:
        return model.model_validate(data)
    except ValidationError as e:
        raise CatalogError(f"{name}: {_why(e, data, root)}") from e


def load(directory: Path | None = None) -> Catalog:
    """The catalogue data of a directory (the bundled one by default), checked; CatalogError names file and product."""
    d = directory or DIR
    meta = _check(CatalogFile, _yaml(d / "catalog.yaml", d), "catalog.yaml")
    cats = _check(CategoriesFile, _yaml(d / "categories.yaml", d), "categories.yaml").categories
    texts = _check(TextsFile, _yaml(d / "texts.yaml", d), "texts.yaml")
    keys = [c.key for c in cats]
    if dup := sorted({k for k in keys if keys.count(k) > 1}):
        raise CatalogError(f"categories.yaml: category listed twice: {', '.join(dup)}")
    files = sorted((d / "products").glob("*.yaml"))
    if extra := sorted({f.stem for f in files} - set(keys)):
        raise CatalogError(f"products/{extra[0]}.yaml: unknown category {extra[0]!r} – the file name must be a key of categories.yaml")
    overlay: list[dict] = []
    seen: dict[str, str] = {}
    by_cat = {f.stem: f for f in files}
    for cat in keys:  # categories.yaml's order, then the order inside the file
        f = by_cat.get(cat)
        if f is None:
            continue
        name = f"products/{f.name}"
        raw = _yaml(f, d)
        if raw is None:
            continue
        if not isinstance(raw, list):
            raise CatalogError(f"{name}: must be a list of products (- key: …)")
        for i, p in enumerate(_check(ProductsFile, {"products": raw}, name, root="products").products):
            where = f"{name}: product {p.key!r} (entry {i + 1})"
            if p.key in seen:
                raise CatalogError(f"{where}: key already used in {seen[p.key]}")
            seen[p.key] = name
            given = p.model_dump(exclude_unset=True)
            if p.label is None:
                if extra := sorted(set(given) - LABELLESS):
                    raise CatalogError(f"{where}: without a label only {', '.join(sorted(LABELLESS - {'key'}))} are allowed (found {', '.join(extra)})")
            elif p.vendor is None:
                raise CatalogError(f"{where}: vendor is missing")
            if p.cloud and p.scheme != "cloud":
                raise CatalogError(f"{where}: a cloud service needs scheme: cloud")
            if p.hint and p.hint not in texts.hints:
                raise CatalogError(f"{where}: hint {p.hint!r} has no text in texts.yaml (hints)")
            if p.where and p.where not in texts.where:
                raise CatalogError(f"{where}: where {p.where!r} has no text in texts.yaml (where)")
            if len(set(p.cpes)) != len(p.cpes):
                raise CatalogError(f"{where}: a CPE is listed twice")
            for eco, _pkg in p.osv or []:
                if eco not in OSV_ECOSYSTEMS:
                    raise CatalogError(f"{where}: osv ecosystem {eco!r} is not one of {', '.join(OSV_ECOSYSTEMS)}")
            _check_rules(p, where, texts)
            # the shape the code used (P(...) rows): key, label, vendor, category, cpes always; the rest only when set
            row = {"key": p.key, "label": p.label, "vendor": p.vendor, "category": cat, "cpes": list(p.cpes)}
            row |= {k: v for k, v in given.items() if k not in row}
            if p.editions:
                row["editions"] = [e.model_dump(by_alias=True, exclude_none=True) for e in p.editions]
            if p.belongs:
                row["belongs"] = [b.model_dump() for b in p.belongs]
            overlay.append(row)
    if "cloud" not in texts.hints:
        raise CatalogError("texts.yaml: the hint 'cloud' (shown with every cloud service) is missing")
    csaf = _csaf(d, {str(o["vendor"]).lower() for o in overlay if o.get("vendor")})
    replaced: dict[str, str] = {}
    for o in overlay:
        for r in o.get("replaces") or []:
            if r in seen or r in replaced:
                raise CatalogError(f"products: {o['key']!r}: replaces {r!r} – a key the catalogue still has (or another entry replaces)")
            replaced[r] = o["key"]
    for o in overlay:
        for b in o.get("belongs") or []:
            if b["to"] not in seen or b["to"] == o["key"]:
                raise CatalogError(f"products: {o['key']!r}: belongs to {b['to']!r} – no other product of the catalogue")
    return Catalog(
        version=meta.catalog_version,
        categories=[c.model_dump() for c in cats],
        texts={"hints": {k: v.model_dump() for k, v in texts.hints.items()}, "where": {k: v.model_dump() for k, v in texts.where.items()}},
        overlay=overlay,
        csaf=csaf,
        cnas=_cnas(d),
        build_maps=_build_maps(d, {o["key"]: o for o in overlay}, texts),
    )


LABELLESS = {"key", "cpes", "scheme", "hint", "osv", "pattern", "pattern_hint", "normalize", "belongs", "cpe_editions", "aliases", "replaces", "lines_only"}


def _check_rules(p: Product, where: str, texts: TextsFile) -> None:
    """The version rules of a product: regular expressions compile, texts exist, editions are versions."""
    import re

    from app.vendor_versions import parse

    for what, rx in [("pattern", p.pattern)] + [("belongs", b.pattern) for b in p.belongs or []]:
        if rx is None:
            continue
        try:
            re.compile(rx)
        except re.error as e:
            raise CatalogError(f"{where}: {what} is no regular expression ({e})") from e
    if p.pattern_hint and p.pattern_hint not in texts.hints:
        raise CatalogError(f"{where}: pattern_hint {p.pattern_hint!r} has no text in texts.yaml (hints)")
    for e in p.editions or []:
        for b in (e.start, e.below):
            if b is not None and parse(p.scheme or "generic", b) is None:
                raise CatalogError(f"{where}: edition {e.name!r}: {b!r} is no version")
    for cpe, _ed in p.cpe_editions or []:
        if cpe not in p.cpes:
            raise CatalogError(f"{where}: cpe_editions names {cpe!r}, not one of the product's CPEs")


def _csaf(d: Path, vendors: set[str]) -> list[dict]:
    """csaf.yaml: unique keys and domains, and every vendor one of the catalogue's (a typo maps nothing)."""
    path = d / "csaf.yaml"
    if not path.is_file():
        return []
    raw = _yaml(path, d) or {"providers": []}
    out: list[dict] = []
    seen: set[str] = set()
    for i, p in enumerate(_check(CsafFile, raw, "csaf.yaml").providers):
        where = f"csaf.yaml: provider {p.key!r} (entry {i + 1})"
        if p.key in seen or p.domain in seen:
            raise CatalogError(f"{where}: key or domain listed twice")
        seen |= {p.key, p.domain}
        if bad := [v for v in p.vendors if v.lower() not in vendors]:
            raise CatalogError(f"{where}: vendor {bad[0]!r} is no vendor of a catalogue product")
        out.append(p.model_dump(exclude_none=True))
    return out


def _cnas(d: Path) -> list[dict]:
    """cnas.yaml: unique keys, and no identifier of two CNAs. Its vendors are not checked here – most of them are
    endoflife.date products' vendors, not this directory's (tests/test_cve_origin.py checks them against the catalogue)."""
    path = d / "cnas.yaml"
    if not path.is_file():
        return []
    raw = _yaml(path, d) or {"cnas": []}
    out: list[dict] = []
    keys: set[str] = set()
    ids: dict[str, str] = {}
    for i, c in enumerate(_check(CnaFile, raw, "cnas.yaml").cnas):
        where = f"cnas.yaml: CNA {c.key!r} (entry {i + 1})"
        if c.key in keys:
            raise CatalogError(f"{where}: key listed twice")
        keys.add(c.key)
        for x in c.ids:
            if (other := ids.get(x.lower())) is not None:
                raise CatalogError(f"{where}: {x!r} is already an identifier of {other!r}")
            ids[x.lower()] = c.key
        out.append(c.model_dump())
    return out


def _build_maps(d: Path, products: dict[str, dict], texts: TextsFile) -> dict:
    """build_maps/*.yaml: each file of a known kind, checked; a product in one table at most."""
    out: dict = {}
    owner: dict[str, str] = {}
    for path in sorted((d / "build_maps").glob("*.yaml")) if (d / "build_maps").is_dir() else []:
        name = f"build_maps/{path.name}"
        raw = _yaml(path, d)
        kind = raw.get("kind") if isinstance(raw, dict) else None
        if kind not in BUILD_MAP_KINDS:
            raise CatalogError(f"{name}: kind must be one of {', '.join(BUILD_MAP_KINDS)}")
        data = _check(BUILD_MAP_KINDS[kind], raw, name)
        keys = ["vcenter", "esxi"] if kind == "vmware" else list(data.products)
        for k in keys:
            if k in owner:
                raise CatalogError(f"{name}: product {k!r} already has a table ({owner[k]})")
            owner[k] = name
        if kind == "vmware":
            _vmware_builds(data, name)
        else:
            _names_map(data, name, products, texts)
        out[path.stem] = data.model_dump(exclude_none=True)
    return out


def _names_map(data: NamesMapFile, name: str, products: dict[str, dict], texts: TextsFile) -> None:
    """A table of names: its products are curated ones, every value a version of their scheme, no name twice."""
    import re

    from app.build_maps import name_key
    from app.vendor_versions import parse

    for k in data.products:
        if k not in products:
            raise CatalogError(f"{name}: product {k!r} is not in the catalogue (products/*.yaml)")
    for what in ("extract", "claims"):
        rx = getattr(data, what)
        if rx is not None:
            try:
                re.compile(rx)
            except re.error as e:
                raise CatalogError(f"{name}: {what} is no regular expression ({e})") from e
    if data.hint and data.hint not in texts.hints:
        raise CatalogError(f"{name}: hint {data.hint!r} has no text in texts.yaml (hints)")
    seen: dict[str, str] = {}
    for i, r in enumerate(data.rows):
        where = f"{name}: {r.value!r} (entry {i + 1})"
        for k in data.products:
            if parse(products[k].get("scheme") or "generic", r.value) is None:
                raise CatalogError(f"{where}: no version of {k!r}'s scheme")
        for n in r.names:
            key = name_key(n, data.strip)
            if not key:
                raise CatalogError(f"{where}: name {n!r} is empty without the strip words")
            if key in seen and seen[key] != r.value:
                raise CatalogError(f"{where}: name {n!r} already stands for {seen[key]!r}")
            seen[key] = r.value


def _vmware_builds(data: VmwareBuildsFile, name: str) -> None:
    """build_maps/vmware.yaml: every release in the vmware scheme, the four-part version of the same line, no version or
    build twice per product (vCenter's and ESXi's builds are different numbers – each table stands alone)."""
    from app.vendor_versions import parse

    for product, rows in (("vcenter", data.vcenter), ("esxi", data.esxi)):
        builds: set[int] = set()
        versions: set[str] = set()
        for i, r in enumerate(rows):
            where = f"{name}: {product} {r.release!r} (entry {i + 1})"
            v = parse("vmware", r.release)
            if v is None:
                raise CatalogError(f"{where}: release is not a version of the vmware scheme")
            if r.build in builds:
                raise CatalogError(f"{where}: build {r.build} listed twice")
            builds.add(r.build)
            if isinstance(r, VcenterBuild):
                if r.version in versions:
                    raise CatalogError(f"{where}: version {r.version} listed twice")
                versions.add(r.version)
                if tuple(int(x) for x in r.version.split(".")[:3]) != (v.key + (0, 0))[:3]:
                    raise CatalogError(f"{where}: version {r.version} is not of the release's line")


def schemas() -> dict[str, dict]:
    """The JSON Schema of each file kind (for editors: `# yaml-language-server: $schema=…` at the top of the files)."""
    out = {name: model.model_json_schema() for name, model in SCHEMA_FILES.items()}
    products = ProductsFile.model_json_schema()
    out["products"] = {"title": "Products of one category", "type": "array", "items": {"$ref": "#/$defs/Product"}, "$defs": products["$defs"]}
    for name, s in out.items():
        s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        s["$comment"] = f"Generated by `python -m app.catalog_data --write-schema` – do not edit ({name}.schema.json)"
    return out


def schema_text(s: dict) -> str:
    return json.dumps(s, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    """`python -m app.catalog_data` checks the catalogue (exit 1 with the problem); `--write-schema` regenerates the schema files."""
    if "--write-schema" in argv:
        (DIR / "schema").mkdir(exist_ok=True)
        for name, s in schemas().items():
            (DIR / "schema" / f"{name}.schema.json").write_text(schema_text(s))
    try:
        cat = load(Path(argv[argv.index("--dir") + 1]) if "--dir" in argv else None)
    except CatalogError as e:
        print(f"catalogue broken: {e}", file=sys.stderr)
        return 1
    print(f"catalogue {cat.version}: {len(cat.overlay)} entries in {len(cat.categories)} categories – ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
