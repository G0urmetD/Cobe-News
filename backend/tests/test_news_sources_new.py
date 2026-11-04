"""Built-in sources of 0.1.7: new ones with their defaults on existing installations; sources taken out (0.1.49: CISA
Alerts, Rockwell Automation – 403 to automatic fetches) leave every installation with what refers to them."""

from pathlib import Path
from urllib.parse import urlsplit

import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update

from app import db, news
from app.models import NewsItem, NewsSource, NotifyRule

NEW_ON = {"cert-at", "certvde", "securityweek-ics", "veeam"}
NEW_OFF = {"cccs", "cert-fr", "watchtowr", "huntress", "oracle", "risky-bulletin", "msrc"}


async def _on() -> dict[str, bool]:
    async with db.session() as s:
        return dict((await s.execute(select(NewsSource.key, NewsSource.enabled))).all())


def test_new_builtin_sources():
    by = news.BUILTIN_BY_KEY
    assert {k for k in NEW_ON | NEW_OFF if by[k].on} == NEW_ON
    assert by["cert-fr"].lang == "fr" and by["cert-at"].lang == "de" and by["msrc"].category == "catalog"
    assert by["msrc"].url == "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
    assert by["cisa-kev"].on is True and not news.RETIRED & set(by)  # the KEV catalog (same host as CISA Alerts) stays
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


async def test_retired_sources_leave_with_what_refers_to_them():
    """CISA Alerts and Rockwell Automation (0.1.49) were built in: at the next start they are gone – a rule that named
    only one of them stops sending news, a story another source carries stays; a source of an admin's own stays."""
    async with db.session() as s:
        cisa = NewsSource(id=uuid.uuid4(), key="cisa", name="CISA Alerts", url="https://www.cisa.gov/cybersecurity-advisories/alerts.xml", site="https://www.cisa.gov", builtin=True, enabled=True, failures=0)
        rock = NewsSource(id=uuid.uuid4(), key="rockwell", name="Rockwell Automation", url="https://www.rockwellautomation.com/bin/rss/security-advisories.xml", site="https://www.rockwellautomation.com", builtin=True, enabled=False, failures=0)
        own = NewsSource(id=uuid.uuid4(), key="own-cisa", name="CISA (own)", url="https://www.cisa.gov/own.xml", site="https://www.cisa.gov", builtin=False, enabled=True, failures=0)
        s.add_all([cisa, rock, own])
        await s.flush()
        s.add(NotifyRule(name="only CISA", kinds=["news"], sources=[str(cisa.id)], enabled=True))
        s.add(NewsItem(source_id=cisa.id, url="https://www.cisa.gov/x", url_key="cisa-x", title="t", title_key="t", published_at=datetime.now(UTC), seq=await news.next_seq(s)))
        await s.commit()
        await news.ensure_sources(s)
    keys = set((await _on()))
    assert not {"cisa", "rockwell"} & keys and "own-cisa" in keys
    async with db.session() as s:
        rule = await s.scalar(select(NotifyRule).where(NotifyRule.name == "only CISA"))
        assert rule.sources == [] and rule.enabled is False
        assert await s.scalar(select(NewsItem).where(NewsItem.url == "https://www.cisa.gov/x")) is None  # carried by nobody else
    async with db.session() as s:
        await news.ensure_sources(s)  # again: nothing left to do

