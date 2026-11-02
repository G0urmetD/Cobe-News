"""The "Dokumentation" page: the handbook files (docs/handbuch) – both languages complete, safe content – and the
endpoint that serves them by role."""

import re
from pathlib import Path

import pytest

from app import __version__, docs
from app.config import get_config

ROOT = Path(__file__).resolve().parents[2] / "docs" / "handbuch"
FENCE = re.compile(r"^\s*(```|~~~)")
LINK = re.compile(r"\]\(([^)\s]*)\)")
# live values the page knows ({{name}}, frontend/src/lib/docs-markdown.ts)
LIVE = {"base_url", "redirect_uri", "version"}
# external hosts the handbook may link to: example domains (RFC 2606) and the public services it explains
PUBLIC_HOSTS = ("example.com", "example.org", "corp.example", "entra.microsoft.com", "api.slack.com", "nvd.nist.gov")


def chapter_files(lang: str) -> list[Path]:
    return sorted(p for p in (ROOT / lang).iterdir() if docs._FILE.match(p.name))


def prose(text: str):
    """(line number, line) of the text outside code blocks, with `code` spans removed."""
    fence = False
    for n, line in enumerate(text.split("\n"), 1):
        if FENCE.match(line):
            fence = not fence
            continue
        if not fence:
            yield n, re.sub(r"`[^`]*`", "", line)


def code_lines(text: str):
    fence = False
    for line in text.split("\n"):
        if FENCE.match(line):
            fence = not fence
        elif fence:
            yield line


# ---------------------------------------------------------------- the files


def test_both_languages_have_every_chapter_and_section():
    """Same files, same audience, same section ids in the same order with the same admin markers – an English reader
    never misses a section, a deep link works in both languages."""
    de, en = chapter_files("de"), chapter_files("en")
    assert len(de) >= 9
    assert [p.name for p in de] == [p.name for p in en]
    for d, e in zip(de, en, strict=True):
        a, b = docs.parse(d.read_text("utf-8")), docs.parse(e.read_text("utf-8"))
        assert a["audience"] == b["audience"], d.name
        assert [(s["id"], s["level"], s["admin"]) for s in a["sections"]] == [(s["id"], s["level"], s["admin"]) for s in b["sections"]], d.name
        assert a["title"] and b["title"] and a["summary"] and b["summary"], d.name


def test_files_stay_below_the_size_limit():
    for p in chapter_files("de") + chapter_files("en"):
        assert p.stat().st_size < docs.MAX_BYTES, p.name


@pytest.mark.parametrize("lang", docs.LANGS)
def test_content_is_safe(lang):
    """No HTML, only https/http, app-internal and term: links, only known live values, no local paths of a machine and no
    hosts outside the example domains and the services the handbook explains."""
    for p in chapter_files(lang):
        text = p.read_text("utf-8")
        for n, line in prose(text):
            where = f"{lang}/{p.name}:{n}"
            assert not re.search(r"<[A-Za-z/!?]", line), f"{where}: HTML or angle bracket outside code: {line!r}"
            assert "![" not in line, f"{where}: images are not supported"
            for target in LINK.findall(line):
                assert re.match(r"^(https?://[^\s]+|/[^\s/][^\s]*|#[a-z0-9-]+|term:[a-z]+)$", target), f"{where}: link {target!r}"
                if target.startswith("http"):
                    host = re.match(r"^https?://([^/:?#]+)", target).group(1).lower()
                    assert any(host == h or host.endswith("." + h) for h in PUBLIC_HOSTS), f"{where}: host {host}"
            for name in re.findall(r"\{\{\s*([a-z_]+)\s*\}\}", line):
                assert name in LIVE, f"{where}: unknown live value {name}"
        assert not re.search(r"~/Tools|/Users/|/home/[a-z]", text), f"{lang}/{p.name}: a local path"
        assert "TODO" not in text, f"{lang}/{p.name}: a TODO"
        # tenant, client or object ids only as obvious examples (00000000-0000-…)
        assert not re.search(r"(?!00000000-0000-)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text), f"{lang}/{p.name}: a real-looking GUID"
        for line in code_lines(text):
            for name in re.findall(r"\{\{\s*([a-z_]+)\s*\}\}", line):
                assert name in LIVE, f"{lang}/{p.name}: unknown live value {name} in code"


@pytest.mark.parametrize("lang", docs.LANGS)
def test_internal_doc_links_resolve(lang):
    """/docs/<chapter>#<section> and #<section> point at a chapter and section that exist – ids never silently break."""
    chapters = {c["id"]: {s["id"] for s in c["sections"]} for c in docs.load(lang)}
    for p in chapter_files(lang):
        own = docs._FILE.match(p.name).group(2)
        for n, line in prose(p.read_text("utf-8")):
            for target in LINK.findall(line):
                if target.startswith("/docs/"):
                    chapter, _, section = target[len("/docs/") :].partition("#")
                    assert chapter in chapters, f"{lang}/{p.name}:{n}: unknown chapter {chapter}"
                    assert not section or section in chapters[chapter], f"{lang}/{p.name}:{n}: unknown section {target}"
                elif target.startswith("#"):
                    assert target[1:] in chapters[own], f"{lang}/{p.name}:{n}: unknown section {target}"


def test_reader_text_has_no_admin_values():
    """What a reader gets never asks for the admin-only live value (the redirect URI) – it would stay a placeholder."""
    for lang in docs.LANGS:
        for c in docs.load(lang):
            if c["audience"] == "admin":
                continue
            assert "{{redirect_uri}}" not in docs.visible(c, admin=False)["body"], c["id"]


# ---------------------------------------------------------------- parsing and filtering

SAMPLE = """---
title: Beispiel
summary: Kurz.
audience: all
---

Einleitung.

## Für alle {#alle}

Text für alle.

```bash
## kein Abschnitt, nur ein Kommentar
```

### Unterpunkt {#unter}

Mehr.

## Nur Admins {#geheim .admin}

Admin-Text mit {{redirect_uri}}.

### Darin {#darin}

Auch Admin.

#### Kleine Überschrift

Noch Admin.

## Wieder alle {#wieder}

Schluss.

### Admin-Unterpunkt {#admin-unter .admin}

Nur Admins.

### Öffentlicher Unterpunkt {#oeffentlich}

Für alle.
"""


def test_parse_reads_head_and_sections():
    ch = docs.parse(SAMPLE)
    assert (ch["title"], ch["summary"], ch["audience"]) == ("Beispiel", "Kurz.", "all")
    assert [(s["id"], s["level"], s["admin"]) for s in ch["sections"]] == [
        ("alle", 2, False),
        ("unter", 3, False),
        ("geheim", 2, True),
        ("darin", 3, False),
        ("wieder", 2, False),
        ("admin-unter", 3, True),
        ("oeffentlich", 3, False),
    ]


def test_reader_view_cuts_admin_sections():
    ch = docs.visible(docs.parse(SAMPLE), admin=False)
    assert [s["id"] for s in ch["sections"]] == ["alle", "unter", "wieder", "oeffentlich"]
    for gone in ("Admin-Text", "Auch Admin", "Noch Admin", "Nur Admins", "redirect_uri"):
        assert gone not in ch["body"]
    for kept in ("Einleitung.", "Text für alle.", "## kein Abschnitt", "Mehr.", "Schluss.", "Für alle."):
        assert kept in ch["body"]
    assert docs.visible(docs.parse(SAMPLE), admin=True)["body"].count("Admin") >= 3


@pytest.mark.parametrize(
    "text",
    [
        "## ohne Kopf {#x}\n",
        "---\ntitle: T\n",
        "---\naudience: all\n---\n",
        "---\ntitle: T\naudience: everyone\n---\n",
        "---\ntitle: T\n---\n## Ohne ID\n",
        "---\ntitle: T\n---\n# H1\n",
        "---\ntitle: T\n---\n## A {#x}\n## B {#x}\n",
    ],
)
def test_parse_refuses_broken_files(text):
    with pytest.raises(docs.DocError):
        docs.parse(text)


# ---------------------------------------------------------------- the endpoint


async def test_endpoint_needs_a_session(client):
    assert (await client.get("/api/docs")).status_code == 401
    assert (await client.get("/api/docs/erste-schritte")).status_code == 401


async def test_admin_gets_every_chapter_with_live_values(admin_client):
    r = await admin_client.get("/api/docs?lang=de")
    assert r.status_code == 200
    body = r.json()
    assert body["lang"] == "de"
    ids = [c["id"] for c in body["chapters"]]
    assert ids == [docs._FILE.match(p.name).group(2) for p in chapter_files("de")]
    assert {"anmeldung", "sicherung", "betrieb", "integrationen"} <= set(ids)
    assert body["live"] == {"base_url": get_config().base_url, "version": __version__, "redirect_uri": get_config().base_url + "/api/auth/oidc/callback"}
    news = next(c for c in body["chapters"] if c["id"] == "news-quellen")
    assert "eigene-quellen" in [s["id"] for s in news["sections"]]
    assert "{#eigene-quellen .admin}" in news["markdown"]


async def test_reader_gets_no_admin_chapters_or_sections(reader_client):
    body = (await reader_client.get("/api/docs?lang=de")).json()
    ids = [c["id"] for c in body["chapters"]]
    assert "erste-schritte" in ids and "faq" in ids
    assert not {"anmeldung", "sicherung", "betrieb", "integrationen"} & set(ids)
    assert all(c["audience"] == "all" for c in body["chapters"])
    for c in body["chapters"]:
        assert ".admin}" not in c["markdown"], c["id"]
        assert not any(s["admin"] for s in c["sections"]), c["id"]
    news = next(c for c in body["chapters"] if c["id"] == "news-quellen")
    assert "eigene-quellen" not in [s["id"] for s in news["sections"]]
    assert "ALLOW_PRIVATE_FEEDS" not in news["markdown"]
    assert "redirect_uri" not in body["live"]
    # the chapter endpoint enforces the same: an admin chapter is refused, an admin section is cut
    assert (await reader_client.get("/api/docs/anmeldung")).status_code == 403
    one = (await reader_client.get("/api/docs/news-quellen")).json()
    assert ".admin}" not in one["markdown"]
    assert "redirect_uri" not in one["live"]


async def test_both_languages_and_the_fallback(admin_client):
    de = (await admin_client.get("/api/docs?lang=de")).json()
    en = (await admin_client.get("/api/docs?lang=en")).json()
    assert en["lang"] == "en" and all(c["lang"] == "en" for c in en["chapters"])
    assert [c["id"] for c in de["chapters"]] == [c["id"] for c in en["chapters"]]
    assert [c["title"] for c in de["chapters"]] != [c["title"] for c in en["chapters"]]
    for x in ("fr", "", "xx-long", None):
        got = (await admin_client.get("/api/docs", params={"lang": x} if x is not None else None)).json()
        assert got["lang"] == "de"
    assert (await admin_client.get("/api/docs/erste-schritte?lang=en-GB")).json()["lang"] == "en"


async def test_unknown_chapter_is_404(admin_client, reader_client):
    for c in (admin_client, reader_client):
        assert (await c.get("/api/docs/gibt-es-nicht")).status_code == 404
        assert (await c.get("/api/docs/..%2F..%2Fetc")).status_code == 404
    r = await admin_client.get("/api/docs/anmeldung?lang=en")
    assert r.status_code == 200 and r.json()["id"] == "anmeldung" and r.json()["audience"] == "admin"


def _write(root: Path, lang: str, name: str, text: str) -> None:
    (root / lang).mkdir(parents=True, exist_ok=True)
    (root / lang / name).write_text(text, "utf-8")


async def test_missing_english_chapter_falls_back_to_german(admin_client, monkeypatch, tmp_path):
    _write(tmp_path, "de", "01-eins.md", "---\ntitle: Eins\n---\n## A {#a}\nText\n")
    _write(tmp_path, "de", "02-zwei.md", "---\ntitle: Zwei\n---\n## B {#b}\nText\n")
    _write(tmp_path, "en", "01-eins.md", "---\ntitle: One\n---\n## A {#a}\nText\n")
    _write(tmp_path, "en", "03-nur-en.md", "---\ntitle: Only EN\n---\n")  # not in German: not served
    _write(tmp_path, "de", "notes.md", "---\ntitle: kein Kapitel\n---\n")  # no NN- prefix: not a chapter
    monkeypatch.setattr(docs, "CANDIDATES", (tmp_path,))
    body = (await admin_client.get("/api/docs?lang=en")).json()
    assert [(c["id"], c["lang"], c["title"]) for c in body["chapters"]] == [("eins", "en", "One"), ("zwei", "de", "Zwei")]


async def test_size_limit_and_broken_files_are_not_served(admin_client, monkeypatch, tmp_path):
    _write(tmp_path, "de", "01-klein.md", "---\ntitle: Klein\n---\nText\n")
    _write(tmp_path, "de", "02-gross.md", "---\ntitle: Groß\n---\n" + "x" * 5000)
    _write(tmp_path, "de", "03-kaputt.md", "## ohne Kopf {#x}\n")
    _write(tmp_path, "de", "04-binaer.md", "---\ntitle: B\n---\n")
    (tmp_path / "de" / "04-binaer.md").write_bytes(b"---\ntitle: \xff\xfe\n---\n")
    monkeypatch.setattr(docs, "CANDIDATES", (tmp_path,))
    monkeypatch.setattr(docs, "MAX_BYTES", 1000)
    body = (await admin_client.get("/api/docs")).json()
    assert [c["id"] for c in body["chapters"]] == ["klein"]
    assert (await admin_client.get("/api/docs/gross")).status_code == 404


async def test_no_handbook_in_the_build(reader_client, monkeypatch, tmp_path):
    monkeypatch.setattr(docs, "CANDIDATES", (tmp_path / "missing",))
    body = (await reader_client.get("/api/docs")).json()
    assert body["chapters"] == []


async def test_bundled_copy_is_read_first(reader_client, monkeypatch, tmp_path):
    image, checkout = tmp_path / "image", tmp_path / "checkout"
    _write(image, "de", "01-bild.md", "---\ntitle: Aus dem Image\n---\n")
    _write(checkout, "de", "01-repo.md", "---\ntitle: Aus dem Repo\n---\n")
    monkeypatch.setattr(docs, "CANDIDATES", (image, checkout))
    assert [c["title"] for c in (await reader_client.get("/api/docs")).json()["chapters"]] == ["Aus dem Image"]
