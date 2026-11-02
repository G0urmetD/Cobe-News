"""The "Version & Changelog" page: the running version and CHANGELOG.md, parsed into one section per version.

The file is copied into the image next to the app (Dockerfile: /srv/CHANGELOG.md beside /srv/app) – version
(app/__init__.py) and notes come from the same build, the page can never show the notes of another release. From a
checkout (tests, uvicorn by hand) the repository root's copy is read."""

import re
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter

from app import __version__
from app.deps import Reader

router = APIRouter(prefix="/api", tags=["about"])

_APP = Path(__file__).resolve().parent
# the image: /srv/CHANGELOG.md (next to /srv/app); a checkout: <repo>/CHANGELOG.md (backend/app → ../../)
CANDIDATES = (_APP.parent / "CHANGELOG.md", _APP.parent.parent / "CHANGELOG.md")
MAX_BYTES = 1_000_000  # our own file – the limit only keeps a mistake (a wrong copy) from being served
MAX_ITEMS = 200  # per version

# "## 0.1.1 – Vendor News" (en dash, em dash or hyphen; the title is optional)
_HEAD = re.compile(r"^##\s+v?(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?)\s*(?:[–—-]\s*(.*?))?\s*$")
_GROUP = re.compile(r"^###(?!#)\s*(.*?)\s*#*\s*$")  # "### Fixes" – a group of the version above
_BULLET = re.compile(r"^[-*+]\s+(.*)$")

# the group headings the changelog uses (CHANGELOG.md, always in this order) – and their English equivalents
KINDS = ("neu", "verbessert", "fixes", "sicherheit", "entfernt", "betrieb")
_KIND_OF = {
    "neu": "neu",
    "new": "neu",
    "added": "neu",
    "verbessert": "verbessert",
    "verbesserungen": "verbessert",
    "improved": "verbessert",
    "changed": "verbessert",
    "fixes": "fixes",
    "fix": "fixes",
    "fixed": "fixes",
    "behoben": "fixes",
    "fehlerbehebungen": "fixes",
    "sicherheit": "sicherheit",
    "security": "sicherheit",
    "entfernt": "entfernt",
    "removed": "entfernt",
    "betrieb": "betrieb",
    "operations": "betrieb",
}


def kind_of(heading: str) -> str:
    """Heading "### Fixes" → "fixes"; a heading the changelog does not define → "other" (shown with its own text)."""
    return _KIND_OF.get(heading.strip(" \t*_:").casefold(), "other")


def parse(text: str) -> list[dict]:
    """Sections in file order (newest first, as written): {version, title, groups, items}.

    A version's bullets sit under small headings ("### Neu", "### Fixes" …): each heading opens a group {kind,
    heading, items} – kind one of KINDS, or "other" for a heading the changelog does not define (its text stays the
    heading). Bullets before the first heading go into an unnamed group (kind "other", heading ""); a heading without
    bullets is dropped. "items" is every item of the version in order, without the headings – for clients that do not
    know groups. A bullet's wrapped lines (indented) are joined with one space; nested bullets are items of their own;
    text outside a version section (the "# Changelog" heading, the intro) is skipped. The items stay markdown-ish text
    – the page renders **bold** and `code`, everything else as plain text."""
    entries: list[dict] = []
    current: dict | None = None
    group: dict | None = None  # the group items go to (None: the unnamed one, opened by its first item)
    item: list[str] | None = None  # the bullet being collected

    def close_item() -> None:
        nonlocal item, group
        if current is not None and item and len(current["items"]) < MAX_ITEMS:
            text = " ".join(item)
            if group is None:
                group = {"kind": "other", "heading": "", "items": []}
                current["groups"].append(group)
            group["items"].append(text)
            current["items"].append(text)
        item = None

    def drop_empty_groups() -> None:
        if current is not None:
            current["groups"] = [g for g in current["groups"] if g["items"]]

    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if re.match(r"^#{1,2}(\s|$)", line):  # "# Changelog", "## 0.1.1 – …": a new section (or none)
            close_item()
            drop_empty_groups()
            m = _HEAD.match(line)
            current = (
                {"version": m.group(1), "title": (m.group(2) or "").strip(), "groups": [], "items": []} if m else None
            )
            group = None
            if current is not None:
                entries.append(current)
            continue
        if current is None:
            continue
        heading = _GROUP.match(line)
        if heading:
            close_item()
            group = {"kind": kind_of(heading.group(1)), "heading": heading.group(1), "items": []}
            current["groups"].append(group)
            continue
        if not stripped:
            close_item()
            continue
        bullet = _BULLET.match(stripped)  # nested bullets: items of their own
        if bullet:
            close_item()
            item = [bullet.group(1).strip()]
        elif item is not None and line[:1].isspace():
            item.append(stripped)  # a wrapped line of the bullet above
        else:
            # a plain paragraph (or a "#### …" heading) in a section – shown like a bullet, not lost
            close_item()
            item = [stripped.lstrip("#").strip()]
    close_item()
    drop_empty_groups()
    return entries


@lru_cache(maxsize=4)
def _parsed(path: str, mtime_ns: int, size: int) -> list[dict]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse(f.read(MAX_BYTES))


def load() -> list[dict]:
    """The bundled changelog, parsed once per file version (it does not change in the image); none found: empty."""
    for p in CANDIDATES:
        try:
            st = p.stat()
        except OSError:
            continue
        if p.is_file():
            return _parsed(str(p), st.st_mtime_ns, st.st_size)
    return []


@router.get("/changelog")
async def changelog(_: Reader) -> dict:
    """The running version and every version's notes – for any signed-in person; nothing in it is secret."""
    from app.vendor_catalog import catalog_version

    entries = load()
    return {
        "version": __version__,
        "catalog_version": catalog_version(),  # the Vendor News catalogue data – versioned on its own (app/catalog)
        "entries": [
            {**e, "groups": [{**g, "items": list(g["items"])} for g in e["groups"]], "items": list(e["items"])}
            for e in entries
        ],
    }
