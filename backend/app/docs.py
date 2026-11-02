"""The "Dokumentation" page: the handbook – Markdown files, one per chapter and language, served to signed-in people.

The files live in docs/handbuch/<lang>/NN-<chapter>.md (format: docs/handbuch/README.md) and are copied into the image
next to the app (Dockerfile: /srv/handbuch beside /srv/app), like CHANGELOG.md – text and version come from the same
build. From a checkout (tests, uvicorn by hand) the repository's copy is read.

Who sees what is decided here, not in the browser: a chapter with `audience: admin` is never sent to a reader, and a
section marked `{#id .admin}` is cut out of the text before it leaves the server. The text is sent as Markdown; the page
renders it with its own small renderer (frontend/src/lib/docs-markdown.ts) – never as HTML."""

import logging
import re
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Query

from app import __version__
from app.auth.entra import redirect_uri
from app.config import get_config
from app.deps import Reader, api_error

log = logging.getLogger("cobe_news.docs")
router = APIRouter(prefix="/api", tags=["docs"])

_APP = Path(__file__).resolve().parent
# the image: /srv/handbuch (next to /srv/app); a checkout: <repo>/docs/handbuch (backend/app → ../../docs)
CANDIDATES = (_APP.parent / "handbuch", _APP.parent.parent / "docs" / "handbuch")
LANGS = ("de", "en")
DEFAULT_LANG = "de"  # the handbook is written in German first; a chapter missing in English falls back to it
MAX_BYTES = 200_000  # per file – our own files; the limit keeps a mistake (a wrong copy, a huge paste) from being served
MAX_CHAPTERS = 50

_FILE = re.compile(r"^(\d{2})-([a-z0-9][a-z0-9-]{0,60})\.md$")
_HEADING = re.compile(r"^(#{2,3})\s+(.+?)\s*\{#([a-z0-9][a-z0-9-]{0,80})((?:\s+\.[a-z]+)*)\}\s*$")
_ANY_HEADING = re.compile(r"^(#{1,6})\s")
_FENCE = re.compile(r"^\s*(```|~~~)")
_META = re.compile(r"^([a-z]+):\s*(.*?)\s*$")


class DocError(ValueError):
    """A chapter file that does not follow the format (docs/handbuch/README.md)."""


def parse(text: str) -> dict:
    """One chapter file → {title, summary, audience, body, sections}. sections: [{id, title, level, admin}] for every
    ## / ### heading in order (headings inside code blocks are code). Raises DocError for a file without the head or
    with a heading without id, a duplicate id, an unknown audience."""
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or lines[0].strip() != "---":
        raise DocError("missing front matter")
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        raise DocError("unterminated front matter") from None
    meta: dict[str, str] = {}
    for raw in lines[1:end]:
        m = _META.match(raw.strip())
        if m:
            meta[m.group(1)] = m.group(2)
    audience = meta.get("audience", "all")
    if audience not in ("all", "admin"):
        raise DocError(f"unknown audience {audience!r}")
    if not meta.get("title"):
        raise DocError("missing title")
    body_lines = lines[end + 1 :]
    sections: list[dict] = []
    seen: set[str] = set()
    fence = False
    for raw in body_lines:
        if _FENCE.match(raw):
            fence = not fence
            continue
        if fence:
            continue
        m = _HEADING.match(raw)
        if m:
            sid = m.group(3)
            if sid in seen:
                raise DocError(f"duplicate section id {sid!r}")
            seen.add(sid)
            classes = m.group(4).split()
            sections.append({"id": sid, "title": m.group(2), "level": len(m.group(1)), "admin": ".admin" in classes})
        elif _ANY_HEADING.match(raw) and len(_ANY_HEADING.match(raw).group(1)) <= 3:
            raise DocError(f"heading without id: {raw.strip()[:80]!r}")
    return {"title": meta["title"], "summary": meta.get("summary", ""), "audience": audience, "body": "\n".join(body_lines).strip("\n"), "sections": sections}


def visible(chapter: dict, admin: bool) -> dict:
    """The chapter as this person may see it: for a reader every `.admin` section is cut out – from its heading to the
    next heading of the same or a higher level (outside code blocks) – and dropped from the section list."""
    if admin:
        return chapter
    out: list[str] = []
    skip_level = 0  # > 0: inside an admin section of this level
    fence = False
    for raw in chapter["body"].split("\n"):
        if _FENCE.match(raw):
            fence = not fence
        elif not fence:
            m = _HEADING.match(raw)
            level = len(m.group(1)) if m else 0
            if m and skip_level and level <= skip_level:
                skip_level = 0
            if m and not skip_level and ".admin" in m.group(4).split():
                skip_level = level
        if not skip_level:
            out.append(raw)
    # a ### inside an admin ## goes with it
    kept: list[dict] = []
    cut = 0
    for s in chapter["sections"]:
        if cut and s["level"] <= cut:
            cut = 0
        if not cut and s["admin"]:
            cut = s["level"]
        if not cut:
            kept.append(s)
    return {**chapter, "body": "\n".join(out).strip("\n"), "sections": kept}


def _root() -> Path | None:
    for p in CANDIDATES:
        if (p / DEFAULT_LANG).is_dir():
            return p
    return None


def _files(root: Path, lang: str) -> list[tuple[str, int, int]]:
    d = root / lang
    if not d.is_dir():
        return []
    out = []
    for f in sorted(d.iterdir()):
        if _FILE.match(f.name) and f.is_file():
            st = f.stat()
            out.append((str(f), st.st_mtime_ns, st.st_size))
    return out[:MAX_CHAPTERS]


@lru_cache(maxsize=8)
def _load(lang: str, files: tuple[tuple[str, int, int], ...], max_bytes: int) -> tuple[dict, ...]:
    chapters = []
    for path, _mtime, size in files:
        name = Path(path).name
        m = _FILE.match(name)
        if size > max_bytes:
            log.warning("docs: %s/%s is larger than %d bytes – not served", lang, name, max_bytes)
            continue
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read(max_bytes + 1)
            if len(text.encode()) > max_bytes:
                raise DocError("too large")
            ch = parse(text)
        except (OSError, UnicodeDecodeError, DocError) as e:
            log.warning("docs: %s/%s not served: %s", lang, name, e)
            continue
        chapters.append({"id": m.group(2), "order": int(m.group(1)), "lang": lang, **ch})
    return tuple(chapters)


def load(lang: str) -> list[dict]:
    """All chapters of a language in order – a chapter missing in it comes from German (marked with its lang). Parsed
    once per file version (the files do not change in the image)."""
    root = _root()
    if root is None:
        return []
    base = list(_load(DEFAULT_LANG, tuple(_files(root, DEFAULT_LANG)), MAX_BYTES))
    if lang == DEFAULT_LANG:
        return base
    own = {c["id"]: c for c in _load(lang, tuple(_files(root, lang)), MAX_BYTES)}
    return [own.get(c["id"], c) for c in base]


def _lang(value: str | None) -> str:
    v = (value or "").strip().lower()[:2]
    return v if v in LANGS else DEFAULT_LANG


def live_values(admin: bool) -> dict:
    """Values of this installation the text may show ({{name}}) – nothing secret; the redirect URI only for admins (the
    chapters that use it are theirs)."""
    out = {"base_url": get_config().base_url, "version": __version__}
    if admin:
        out["redirect_uri"] = redirect_uri()
    return out


def _out(ch: dict, admin: bool) -> dict:
    v = visible(ch, admin)
    return {
        "id": v["id"],
        "title": v["title"],
        "summary": v["summary"],
        "audience": v["audience"],
        "lang": v["lang"],
        "sections": [{"id": s["id"], "title": s["title"], "level": s["level"], "admin": s["admin"]} for s in v["sections"]],
        "markdown": v["body"],
    }


@router.get("/docs")
async def docs_index(user: Reader, lang: str | None = Query(None, max_length=10)) -> dict:
    """Every chapter this person may read, with its text (one request: the page searches across chapters)."""
    admin = user.role == "admin"
    want = _lang(lang)
    chapters = [_out(c, admin) for c in load(want) if admin or c["audience"] != "admin"]
    return {"lang": want, "chapters": chapters, "live": live_values(admin)}


@router.get("/docs/{chapter}")
async def docs_chapter(chapter: str, user: Reader, lang: str | None = Query(None, max_length=10)) -> dict:
    """One chapter – unknown: 404; an admin chapter for a reader: 403."""
    admin = user.role == "admin"
    want = _lang(lang)
    found = next((c for c in load(want) if c["id"] == chapter), None)
    if found is None:
        raise api_error(404, "not_found")
    if found["audience"] == "admin" and not admin:
        raise api_error(403, "forbidden")
    return {**_out(found, admin), "live": live_values(admin)}
