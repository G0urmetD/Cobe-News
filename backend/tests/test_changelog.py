"""The "Version & Changelog" page: CHANGELOG.md parsed into versions, served to any signed-in person."""

from app import __version__, changelog
from app.vendor_catalog import catalog_version

SAMPLE = """# Changelog

Versionierung: 0.1.x – jede Änderung erhöht die letzte Stelle.

## 0.1.2 – Zweite Version

- Neuer Punkt **Fett** mit `code`: eine lange Zeile, die
  auf der nächsten Zeile weitergeht
  und noch einer.
- Zweiter Punkt.
  - verschachtelt

### Hinweis
Ein Absatz ohne Spiegelstrich.

## 0.1.1 - Bindestrich statt Gedankenstrich
* Stern als Aufzählung

## 0.1.0

- ohne Titel

## Unveröffentlicht

- gehört zu keiner Version
"""


def test_parse_sections_items_and_wrapped_lines():
    entries = changelog.parse(SAMPLE)
    assert [e["version"] for e in entries] == ["0.1.2", "0.1.1", "0.1.0"]
    first = entries[0]
    assert first["title"] == "Zweite Version"
    assert first["items"] == [
        "Neuer Punkt **Fett** mit `code`: eine lange Zeile, die auf der nächsten Zeile weitergeht und noch einer.",
        "Zweiter Punkt.",
        "verschachtelt",
        "Ein Absatz ohne Spiegelstrich.",
    ]
    # bullets before any "###" form an unnamed group; an unknown heading keeps its text, kind "other"
    assert first["groups"] == [
        {"kind": "other", "heading": "", "items": first["items"][:3]},
        {"kind": "other", "heading": "Hinweis", "items": ["Ein Absatz ohne Spiegelstrich."]},
    ]
    assert entries[1] == {
        "version": "0.1.1",
        "title": "Bindestrich statt Gedankenstrich",
        "groups": [{"kind": "other", "heading": "", "items": ["Stern als Aufzählung"]}],
        "items": ["Stern als Aufzählung"],
    }
    assert entries[2] == {
        "version": "0.1.0",
        "title": "",
        "groups": [{"kind": "other", "heading": "", "items": ["ohne Titel"]}],
        "items": ["ohne Titel"],
    }


GROUPED = """# Changelog

## 0.1.4 – Versionen-Tab und Fixes

### Neu
- Reiter **Versionen**
- Formular „Neue Version eintragen“

### Verbessert
- Status-Chips
### Fixes
- PAN-OS: zweite CVE
  über zwei Zeilen
### Sicherheit
- Cookies
### Entfernt
- alte Seite
### Betrieb
- `SMTP_ALLOW_INTERNAL`
### Leer

## 0.1.3

- vor der ersten Überschrift
### fixes:
- klein geschrieben, mit Doppelpunkt
### Security
- englisch
#### Unterpunkt
- darunter
"""


def test_parse_groups_in_file_order():
    new, old = changelog.parse(GROUPED)
    assert new["title"] == "Versionen-Tab und Fixes"
    assert [(g["kind"], g["heading"], g["items"]) for g in new["groups"]] == [
        ("neu", "Neu", ["Reiter **Versionen**", "Formular „Neue Version eintragen“"]),
        ("verbessert", "Verbessert", ["Status-Chips"]),
        ("fixes", "Fixes", ["PAN-OS: zweite CVE über zwei Zeilen"]),
        ("sicherheit", "Sicherheit", ["Cookies"]),
        ("entfernt", "Entfernt", ["alte Seite"]),
        ("betrieb", "Betrieb", ["`SMTP_ALLOW_INTERNAL`"]),
    ]  # "### Leer" has no items: dropped
    assert new["items"] == [i for g in new["groups"] for i in g["items"]]  # the flat list, without headings
    assert [(g["kind"], g["heading"]) for g in old["groups"]] == [
        ("other", ""),
        ("fixes", "fixes:"),
        ("sicherheit", "Security"),
    ]
    # "####" is no group: its text is an item of the group above, like before
    assert old["groups"][-1]["items"] == ["englisch", "Unterpunkt", "darunter"]


def test_kind_of():
    assert [changelog.kind_of(h) for h in changelog.KINDS] == list(changelog.KINDS)
    assert changelog.kind_of("  **Fixes**  ") == "fixes"
    assert changelog.kind_of("New") == "neu"
    assert changelog.kind_of("Hinweise") == "other"


def test_item_limit_counts_the_whole_version(monkeypatch):
    monkeypatch.setattr(changelog, "MAX_ITEMS", 2)
    (entry,) = changelog.parse("## 1.0.0\n### Neu\n- a\n- b\n### Fixes\n- c\n")
    assert entry["items"] == ["a", "b"]
    assert entry["groups"] == [{"kind": "neu", "heading": "Neu", "items": ["a", "b"]}]


def test_parse_empty_and_intro_only():
    assert changelog.parse("") == []
    assert changelog.parse("# Changelog\n\n- kein Abschnitt\n") == []


def test_repository_changelog_has_the_running_version():
    """Every release bumps the version and writes its notes – the page shows them as "Neu in …"."""
    versions = [e["version"] for e in changelog.load()]
    assert versions, "CHANGELOG.md not found"
    assert __version__ in versions
    assert all(e["items"] for e in changelog.load())


def test_repository_changelog_uses_the_groups():
    """Every version lists its changes under the small headings (### Neu, ### Verbessert, ### Fixes, ### Sicherheit,
    ### Entfernt, ### Betrieb) – only known ones, each at most once, always in that order, none empty."""
    for e in changelog.load():
        kinds = [g["kind"] for g in e["groups"]]
        assert kinds, f"{e['version']}: no groups"
        assert "other" not in kinds, f"{e['version']}: a bullet outside a known heading ({e['groups']})"
        assert kinds == sorted(set(kinds), key=changelog.KINDS.index), f"{e['version']}: headings {kinds}"
        assert all(g["items"] for g in e["groups"])
        assert e["items"] == [i for g in e["groups"] for i in g["items"]]


async def test_endpoint_needs_a_session(client):
    r = await client.get("/api/changelog")
    assert r.status_code == 401


async def test_endpoint_for_a_reader(reader_client):
    r = await reader_client.get("/api/changelog")
    assert r.status_code == 200
    data = r.json()
    assert data["version"] == __version__
    assert set(data) == {"version", "catalog_version", "entries"}
    assert data["catalog_version"] == catalog_version()  # the catalogue data, versioned on its own
    assert data["entries"][0]["version"] == __version__
    assert all(set(e) == {"version", "title", "groups", "items"} for e in data["entries"])
    groups = data["entries"][0]["groups"]
    assert groups and all(set(g) == {"kind", "heading", "items"} for g in groups)


async def test_endpoint_without_a_file(reader_client, monkeypatch, tmp_path):
    monkeypatch.setattr(changelog, "CANDIDATES", (tmp_path / "missing.md",))
    r = await reader_client.get("/api/changelog")
    assert r.status_code == 200
    assert r.json() == {"version": __version__, "catalog_version": catalog_version(), "entries": []}


async def test_endpoint_reads_the_bundled_copy_first(reader_client, monkeypatch, tmp_path):
    bundled = tmp_path / "CHANGELOG.md"
    bundled.write_text(SAMPLE, encoding="utf-8")
    monkeypatch.setattr(changelog, "CANDIDATES", (bundled, tmp_path / "other.md"))
    r = await reader_client.get("/api/changelog")
    assert [e["version"] for e in r.json()["entries"]] == ["0.1.2", "0.1.1", "0.1.0"]
