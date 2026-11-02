"""Built-in sources of 0.1.7: twelve new ones with their defaults on existing installations, and
CISA Alerts off by default – switched off where no admin ever switched it, an admin's choice stays."""

from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import select, update

from app import db, news
from app.models import NewsSource

NEW_ON = {"cert-at", "certvde", "securityweek-ics", "veeam"}
NEW_OFF = {"cccs", "cert-fr", "watchtowr", "huntress", "rockwell", "oracle", "risky-bulletin", "msrc"}


async def _on() -> dict[str, bool]:
    async with db.session() as s:
        return dict((await s.execute(select(NewsSource.key, NewsSource.enabled))).all())


def test_new_builtin_sources():
    by = news.BUILTIN_BY_KEY
    assert {k for k in NEW_ON | NEW_OFF if by[k].on} == NEW_ON
    assert by["cert-fr"].lang == "fr" and by["cert-at"].lang == "de" and by["msrc"].category == "catalog"
    assert by["msrc"].url == "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
    assert by["cisa"].on is False and by["cisa-kev"].on is True  # the KEV catalog (same host) stays on
    # every feed host is in the list of outbound hosts in docs/BETRIEB.md
    readme = (Path(__file__).parents[2] / "docs" / "BETRIEB.md").read_text()
    missing = sorted(h for h in {urlsplit(b.url).hostname for b in news.BUILTIN} if f"`{h}`" not in readme)
    assert not missing, missing


async def test_new_sources_arrive_with_their_default():
    """An installation from before 0.1.7: the new keys come with their default, existing switches stay."""
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.key == "zdi").values(enabled=True))  # an admin's choice
        await s.execute(update(NewsSource).where(NewsSource.key == "heise").values(enabled=False))
        await s.execute(NewsSource.__table__.delete().where(NewsSource.key.in_(NEW_ON | NEW_OFF)))  # as before this version
        await s.commit()
        await news.ensure_sources(s)
    on = await _on()
    assert all(on[k] for k in NEW_ON) and not any(on[k] for k in NEW_OFF)
    assert on["zdi"] is True and on["heise"] is False


async def test_cisa_alerts_off_unless_an_admin_chose_it(admin_client):
    # a new installation: off
    assert (await _on())["cisa"] is False
    # an older installation that never touched it (on, nothing recorded): switched off at the next start
    async with db.session() as s:
        await s.execute(update(NewsSource).where(NewsSource.key == "cisa").values(enabled=True, switched_at=None))
        await s.commit()
        await news.ensure_sources(s)
    assert (await _on())["cisa"] is False
    # an admin switches it on: it stays on, start after start
    sid = next(x["id"] for x in (await admin_client.get("/api/admin/news")).json()["sources"] if x["key"] == "cisa")
    assert (await admin_client.patch(f"/api/admin/news/sources/{sid}", json={"enabled": True})).json()["enabled"] is True
    for _ in range(2):
        async with db.session() as s:
            await news.ensure_sources(s)
    assert (await _on())["cisa"] is True
    # renaming nothing, switching another source: only that one is recorded
    async with db.session() as s:
        rows = dict((await s.execute(select(NewsSource.key, NewsSource.switched_at))).all())
    assert rows["cisa"] is not None and rows["heise"] is None

