"""A feed's address in one spelling (0.1.51): the bug hunt of 0.1.50 added "https://FEEDS.example.test/rss" next to
"https://feeds.example.test/rss" – the same feed twice, fetched twice. Host in lower case, an international name in its
ASCII form, no default port; path and query stay as typed."""

import uuid

import pytest
from sqlalchemy import select

from app import db
from app.models import NewsSource
from app.netaddr import normal_url


@pytest.mark.parametrize(
    ("typed", "stored"),
    [
        ("https://FEEDS.Example.TEST/rss", "https://feeds.example.test/rss"),
        ("HTTPS://feeds.example.test:443/rss", "https://feeds.example.test/rss"),
        ("https://feeds.example.test:8443/RSS?Lang=DE", "https://feeds.example.test:8443/RSS?Lang=DE"),
        ("https://bücher.example/feed", "https://xn--bcher-kva.example/feed"),
        ("https://[2001:DB8::1]:443/feed", "https://[2001:db8::1]/feed"),
        ("  https://feeds.example.test/rss ", "https://feeds.example.test/rss"),
    ],
)
def test_one_spelling(typed, stored):
    assert normal_url(typed) == stored


def test_unparseable_stays_as_it_is():
    assert normal_url("https://0[x:3/") == "https://0[x:3/"
    assert normal_url("not a url") == "not a url"


async def test_the_same_feed_in_another_spelling_is_refused(admin_client):
    add = lambda url, name="Eigener Feed": admin_client.post("/api/admin/news/sources", json={"name": name, "url": url})  # noqa: E731
    r = await add("https://Feeds.Example.test:443/rss")
    assert r.status_code == 200 and r.json()["url"] == "https://feeds.example.test/rss"
    for other in ("https://FEEDS.example.test/rss", "https://feeds.example.test:443/rss", "https://feeds.example.test/rss"):
        r = await add(other, "Doppelt")
        assert r.status_code == 409 and r.json()["detail"]["code"] == "news_source_exists", other
    assert (await add("https://feeds.example.test/RSS", "Anderer Pfad")).status_code == 200  # another path: another feed


async def test_a_source_stored_before_in_another_spelling_counts(admin_client):
    """A source of 0.1.50 or older may be stored with an upper-case host: a new one with the same address is refused,
    and the old one is left as it is (nothing deleted)."""
    async with db.session() as s:
        s.add(NewsSource(id=uuid.uuid4(), key="custom-old", name="Alt", url="https://OLD.example.test:443/feed", site="", builtin=False, enabled=True, failures=0))
        await s.commit()
    r = await admin_client.post("/api/admin/news/sources", json={"name": "Neu", "url": "https://old.example.test/feed"})
    assert r.status_code == 409
    other = (await admin_client.post("/api/admin/news/sources", json={"name": "Zweit", "url": "https://two.example.test/feed"})).json()
    r = await admin_client.patch(f"/api/admin/news/sources/{other['id']}", json={"url": "https://Old.Example.Test/feed"})
    assert r.status_code == 409
    async with db.session() as s:
        assert await s.scalar(select(NewsSource.url).where(NewsSource.key == "custom-old")) == "https://OLD.example.test:443/feed"
