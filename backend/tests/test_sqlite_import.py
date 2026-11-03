"""The one-off move of a 0.1.15 SQLite file into PostgreSQL (app/sqlite_import.py): every table, the types converted,
SQLite's rowid kept as the order, verified before the commit, all or nothing, never into a database that holds data,
the file itself never changed – and the automatic import at the app's start (once, with a marker)."""

import hashlib
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import column, create_engine, func, insert, select, table

from app import db, news, sqlite_import
from app.auth import passwords
from app.models import NewsItem, NewsItemSource, NewsSource, Setting, StoryDetail, User, VendorAdvisory, VendorEvent, VendorFollow
from tests.conftest import empty_tables

SCHEMA = Path(__file__).parent / "fixtures" / "sqlite-0.1.15.sql"
T0 = datetime(2026, 10, 1, 12, 30, 15, 123456, tzinfo=UTC)


def _table(name: str):  # noqa: ANN202
    return next(t for t in sqlite_import.tables() if t.name == name)


def make_old(path: Path, *, wal: bool = False) -> dict:
    """A SQLite file as 0.1.15 left it (its schema, its storage: hex uuids, naive UTC times, JSON text, 0/1) – written
    through the models' tables on SQLite, as 0.1.15 wrote them."""
    con = sqlite3.connect(path)
    con.executescript(SCHEMA.read_text())
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
    con.close()
    eng = create_engine(f"sqlite:///{path}")
    ids = {"a": uuid.uuid4(), "b": uuid.uuid4(), "c": uuid.uuid4(), "item": uuid.uuid4(), "user": uuid.uuid4(), "temp": uuid.uuid4(), "follow": uuid.uuid4()}

    def cols(table_name: str, /, **row) -> tuple:  # noqa: ANN003
        return _table(table_name), row

    rows = [
        cols("news_sources", id=ids["a"], key="heise", name="heise online", url="https://www.heise.de/rss", site="https://www.heise.de", builtin=True, enabled=True, failures=0, created_at=T0, logo=b"\x89PNG\x00\xff", logo_type="image/png"),
        cols("news_sources", id=ids["b"], key="bsi", name="BSI – Lücke", url="https://bsi.example.org/rss", site="", builtin=True, enabled=False, failures=2, created_at=T0, switched_at=T0),
        cols("news_sources", id=ids["c"], key="custom-x", name="Eigener", url="https://feed.example.org/x", site="", builtin=False, enabled=True, failures=0, created_at=T0),
        cols(
            "news_items",
            id=ids["item"],
            source_id=ids["a"],
            url="https://www.heise.de/news/x.html",
            url_key="k1",
            title="Lücke in „FortiOS“ 🛡️",
            title_key="t1",
            summary="ß und é",
            content_html="<p>x</p>",
            published_at=T0,
            fetched_at=T0 + timedelta(minutes=5),
            severity="critical",
            reasons=[{"kind": "cvss", "value": "9.8"}, {"kind": "exploited"}],
            cves=["CVE-2026-0001", "CVE-2026-0002"],
            also_in=["BSI – Lücke"],
            backlog=False,
            search="lucke in fortios",
            seq=7,
        ),
        cols("news_item_sources", item_id=ids["item"], source_id=ids["c"]),  # rowid 1: came first
        cols("news_item_sources", item_id=ids["item"], source_id=ids["b"]),  # rowid 2
        cols("counters", name="news_seq", value=7),
        cols("counters", name="news_pruned_before", value=2_000_000_000),
        cols("settings", key="news", value={"enabled": True, "every_min": 30, "rev": 4}),
        cols("settings", key="setup", value={"completed": True, "token_hash": "", "token_expires": 0}),
        cols("users", id=ids["user"], username="anna", display_name="Anna", role="admin", auth_source="local", password_hash="$argon2id$x", must_change_password=False, totp_secret_enc="v1:abc", is_active=True, is_emergency=True, desktop={}, created_at=T0, version=3),
        cols("users", id=ids["temp"], username="bert", display_name="Bert", role="reader", auth_source="local", password_hash="$argon2id$y", must_change_password=True, is_active=True, is_emergency=False, desktop={}, created_at=T0, version=1),
        cols(
            "story_details",
            item_id=ids["item"],
            kind="nvd",
            ident="CVE-2026-0001",
            status="ok",
            data={"cvss": [{"score": 9.8}], "products": [{"name": "FortiOS", "fixed": ["7.4.9"]}], "nested": {"a": [1, 2.5, None, True]}},
            fetched_at=T0,
            next_try_at=None,
            failures=0,
        ),
        cols("vendor_follows", id=ids["follow"], product="fortios", enabled=True, note="RZ", tags=["fw", "prod"], custom=None, created_at=T0, updated_at=T0),
        cols("vendor_advisories", id="nvd:CVE-2026-0001", source="nvd", ident="CVE-2026-0001", title="t", summary="s", url="https://nvd.example.org", cves=["CVE-2026-0001"], cvss=9.8, severity="critical", exploited=True, published_at=T0, fetched_at=T0, data={"configs": []}),
    ]
    for i in range(5):  # rowids 1..5, then one deleted: the identity must go past the highest, not the count
        rows.append(cols("vendor_events", id=uuid.uuid4(), key=f"vuln:fortios:7.4.8:nvd:CVE-2026-000{i}", kind="vuln", product="fortios", severity="high", data={"cves": [f"CVE-2026-000{i}"]}, baseline=i == 0, scope="vuln:fortios:7.4.8", created_at=T0))
    with eng.begin() as conn:
        for t, row in rows:
            # only the columns given (a column added after 0.1.15 – news_items.topics – has a default, but no place in the file)
            conn.execute(insert(table(t.name, *(column(k, t.c[k].type) for k in row))).values(**row))
        conn.exec_driver_sql("DELETE FROM vendor_events WHERE rowid = 3")
    eng.dispose()
    return ids


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
async def empty():
    await empty_tables()


async def test_everything_is_moved_with_its_types(tmp_path, empty):
    path = tmp_path / "news.db"
    ids = make_old(path)
    before = sha(path)
    report = await sqlite_import.run(path)
    assert sha(path) == before  # the file is the way back: never changed
    assert report.tables["news_items"] == 1 and report.tables["vendor_events"] == 4 and report.tables["news_sources"] == 3 and report.checked > 0
    async with db.session() as s:
        item = await s.get(NewsItem, ids["item"])
        assert item.title == "Lücke in „FortiOS“ 🛡️" and item.published_at == T0 and item.published_at.tzinfo is not None
        assert item.reasons == [{"kind": "cvss", "value": "9.8"}, {"kind": "exploited"}] and item.cves == ["CVE-2026-0001", "CVE-2026-0002"]
        assert (await s.get(NewsSource, ids["a"])).logo == b"\x89PNG\x00\xff"
        assert (await s.get(NewsSource, ids["b"])).enabled is False
        det = await s.get(StoryDetail, ids["item"])
        assert det.data["nested"] == {"a": [1, 2.5, None, True]}
        assert (await s.get(User, ids["user"])).version == 3
        # a temporary password brought along (an account made long ago): counted from the import, not run out on arrival
        bert, anna = await s.get(User, ids["temp"]), await s.get(User, ids["user"])
        assert anna.temp_password_at is None and datetime.now(UTC) - bert.temp_password_at < timedelta(minutes=5)
        assert not passwords.temp_expired(bert, passwords.TEMP_DAYS) and passwords.temp_expired(bert, 1, datetime.now(UTC) + timedelta(days=2))
        assert (await s.get(VendorAdvisory, "nvd:CVE-2026-0001")).cvss == 9.8
        assert (await s.get(VendorFollow, ids["follow"])).tags == ["fw", "prod"]
        # the order the further sources came in (SQLite's rowid)
        assert list(await s.scalars(select(NewsItemSource.source_id).where(NewsItemSource.item_id == ids["item"]).order_by(NewsItemSource.n))) == [ids["c"], ids["b"]]
        assert sorted(await s.scalars(select(VendorEvent.n))) == [1, 2, 4, 5]
        # the next number goes past the highest one taken over
        s.add(VendorEvent(key="eol:x", kind="eol", product="fortios", severity="info", data={}))
        await s.commit()
        assert await s.scalar(select(func.max(VendorEvent.n))) == 6
        assert await news.last_seq(s) == 7 and await news.next_seq(s) == 8
        assert (await s.get(Setting, "news")).value["rev"] == 4
        marker = (await s.get(Setting, sqlite_import.MARKER)).value
        assert marker["rows"]["news_items"] == 1 and marker["from"] == "sqlite"


async def test_a_wal_file_with_unwritten_pages_is_read_as_it_is(tmp_path, empty):
    """A 0.1.15 that ended hard leaves news.db-wal behind: read (read-only) with it, the database and its WAL unchanged
    (the -shm file is SQLite's shared lock index – every reader touches it)."""
    path = tmp_path / "news.db"
    make_old(path, wal=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("UPDATE news_sources SET name = 'nur im WAL' WHERE key = 'heise'")
    con.commit()  # held open: the change is only in the -wal file
    try:
        files = {p.name: sha(p) for p in tmp_path.iterdir() if not p.name.endswith("-shm")}
        assert "news.db-wal" in files
        await sqlite_import.run(path)
        assert {p.name: sha(p) for p in tmp_path.iterdir() if not p.name.endswith("-shm")} == files
    finally:
        con.close()
    async with db.session() as s:
        assert await s.scalar(select(NewsSource.name).where(NewsSource.key == "heise")) == "nur im WAL"


async def test_refuses_a_database_that_holds_data(tmp_path):
    """The test's database has its sources and an account: nothing is imported, nothing changed (the sources alone are
    only what every start seeds – see test_manual_import_after_the_app_started_once)."""
    path = tmp_path / "news.db"
    make_old(path)
    async with db.session() as s:
        s.add(User(username="anna", display_name="Anna", role="admin", auth_source="local"))
        await s.commit()
        n = await s.scalar(select(func.count()).select_from(NewsSource))
    with pytest.raises(sqlite_import.ImportRefused, match="already holds data"):
        await sqlite_import.run(path)
    async with db.session() as s:
        assert await s.scalar(select(func.count()).select_from(NewsSource)) == n and await s.get(Setting, sqlite_import.MARKER) is None


async def test_refuses_a_file_of_an_older_version(tmp_path, empty):
    path = tmp_path / "news.db"
    make_old(path)
    con = sqlite3.connect(path)
    con.execute("DROP INDEX ix_vendor_events_scope")
    con.execute("ALTER TABLE vendor_events DROP COLUMN scope")
    con.close()
    with pytest.raises(sqlite_import.ImportRefused, match=r"not of 0\.1\.15.*vendor_events\.scope"):
        await sqlite_import.run(path)


async def test_a_failure_half_way_keeps_nothing(tmp_path, empty, monkeypatch):
    path = tmp_path / "news.db"
    make_old(path)

    async def broken(conn, src, counts):  # noqa: ANN001
        raise sqlite_import.ImportRefused("story_details: differs – nothing kept")

    monkeypatch.setattr(sqlite_import, "_verify", broken)
    with pytest.raises(sqlite_import.ImportRefused):
        await sqlite_import.run(path)
    async with db.engine().connect() as conn:
        assert await sqlite_import.target_empty(conn)  # rolled back: the next start tries again from scratch


async def test_a_difference_is_found_before_the_commit(tmp_path, empty, monkeypatch):
    """The verification compares values, not only counts: a row changed on the way is refused."""
    path = tmp_path / "news.db"
    make_old(path)
    real = sqlite_import._read

    def tampered(src, table, after, limit, *rest):  # noqa: ANN001, ANN002
        rows = real(src, table, after, limit, *rest)
        for r in rows:
            if table.name == "story_details":
                r["data"] = {**r["data"], "cvss": [{"score": 1.0}]}
        return rows

    monkeypatch.setattr(sqlite_import, "_read", tampered)
    with pytest.raises(sqlite_import.ImportRefused, match="story_details.data"):
        await sqlite_import.run(path)
    async with db.engine().connect() as conn:
        assert await sqlite_import.target_empty(conn)


async def test_on_start_imports_once_and_leaves_a_note(tmp_path, empty, caplog):
    path = tmp_path / "news.db"
    make_old(path)
    with caplog.at_level("INFO", logger="cobe_news.db"):
        report = await sqlite_import.on_start(path)
    assert report is not None and any("import of news.db done" in r.getMessage() for r in caplog.records)
    assert (tmp_path / "news.db.imported-to-postgresql.txt").is_file()
    assert await sqlite_import.on_start(path) is None  # marked: the next start imports nothing


async def test_on_start_without_a_file_or_with_an_empty_one_does_nothing(tmp_path, empty):
    assert await sqlite_import.on_start(tmp_path / "news.db") is None
    path = tmp_path / "news.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA.read_text())  # a 0.1.15 that never ran its setup
    con.close()
    assert await sqlite_import.on_start(path) is None
    async with db.engine().connect() as conn:
        assert await sqlite_import.target_empty(conn)


async def test_on_start_does_not_import_into_a_database_with_data(tmp_path, caplog):
    path = tmp_path / "news.db"
    make_old(path)
    with caplog.at_level("WARNING", logger="cobe_news.db"):
        assert await sqlite_import.on_start(path) is None
    assert any("without an import marker" in r.getMessage() for r in caplog.records)


async def test_on_start_refuses_to_start_on_a_broken_file(tmp_path, empty):
    """The import cannot be done: the app must not start (and serve an empty database while the file holds the data)."""
    path = tmp_path / "news.db"
    path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
    with pytest.raises(sqlite_import.ImportRefused):
        await sqlite_import.on_start(path)


async def test_control_characters_in_the_file_are_dropped_and_counted(tmp_path, empty):
    """Bug hunt 0.1.16 M4: SQLite stored a NUL, PostgreSQL refuses it in text and JSON – the import ended with a raw
    database error and the app did not start. Now the control characters are dropped and the report counts them."""
    from sqlalchemy import text

    path = tmp_path / "news.db"
    ids = make_old(path)
    eng = create_engine(f"sqlite:///{path}")
    with eng.begin() as c:
        c.execute(text("UPDATE news_items SET summary = :s"), {"s": "before\x00after\x07"})
        c.execute(text("UPDATE story_details SET data = :d"), {"d": '{"nested": {"a": [1, 2.5, null, true]}, "note": "x\\u0000y"}'})
    eng.dispose()
    report = await sqlite_import.run(path)
    assert report.cleaned == {"news_items": 1, "story_details": 1}
    assert any("1 values without control characters" in line for line in report.lines())
    async with db.session() as s:
        assert (await s.get(NewsItem, ids["item"])).summary == "beforeafter"
        assert (await s.get(StoryDetail, ids["item"])).data["note"] == "xy"
        assert (await s.get(Setting, sqlite_import.MARKER)).value["cleaned"] == {"news_items": 1, "story_details": 1}


async def test_manual_import_after_the_app_started_once(tmp_path, empty):
    """Bug hunt 0.1.16 L2: the manual import in docs/BETRIEB.md (SQLITE_IMPORT=0, `migrate-sqlite` in the running app) always refused,
    because the app's start had seeded the built-in sources and a setup token. That seed makes way now; real data does not."""
    from app.auth_api import issue_setup_token

    path = tmp_path / "news.db"
    ids = make_old(path)
    async with db.session() as s:  # what the app's start does right after the migrations
        await news.ensure_sources(s)
        await issue_setup_token(s)
    report = await sqlite_import.run(path)
    assert report.tables["news_sources"] == 3
    async with db.session() as s:
        assert (await s.get(NewsItem, ids["item"])) is not None
        assert len(list(await s.scalars(select(NewsSource)))) == 3  # the file's sources, not the seed beside them
    # an account or an own source is data: refused as before
    await empty_tables()
    async with db.session() as s:
        await news.ensure_sources(s)
        s.add(NewsSource(key="custom-x", name="X", url="https://x.example.org/rss", site="", builtin=False))
        await s.commit()
    with pytest.raises(sqlite_import.ImportRefused, match="already holds data"):
        await sqlite_import.run(path)
