"""Bodies from servers Cobe News does not control: the size limit holds after decompression too, stacked encodings are
refused, and a hostile feed title cannot stall the app."""

import gzip

import httpx
import pytest

from app import bounded, news


async def _get(content: bytes, encoding: str | None):
    headers = {"content-encoding": encoding} if encoding else {}

    async def body():  # streamed, as from the network – not pre-read
        for i in range(0, len(content), 16384):
            yield content[i : i + 16384]

    t = httpx.MockTransport(lambda r: httpx.Response(200, content=body(), headers=headers))
    c = httpx.AsyncClient(transport=t)
    return c, c.stream("GET", "https://feed.example/x")


async def _read(content: bytes, encoding: str | None, limit: int) -> bytes:
    c, s = await _get(content, encoding)
    async with c, s as resp:
        return await bounded.read_limited(resp, limit)


async def test_plain_and_single_gzip_are_read():
    assert await _read(b"hello", None, 100) == b"hello"
    assert await _read(gzip.compress(b"hello" * 10), "gzip", 100) == b"hello" * 10


async def test_a_cut_off_compressed_body_is_refused_not_taken_as_complete():
    """Security review 0.1.16 L14: a gzip or deflate stream that ends early was taken as the whole body."""
    import zlib

    full = gzip.compress(b"<rss>" + b"x" * 50_000 + b"</rss>")
    with pytest.raises(bounded.BadEncoding, match="truncated"):
        await _read(full[: len(full) // 2], "gzip", 1_000_000)
    deflated = zlib.compress(b"hello" * 1000)
    with pytest.raises(bounded.BadEncoding, match="truncated"):
        await _read(deflated[:-6], "deflate", 1_000_000)
    assert await _read(deflated, "deflate", 1_000_000) == b"hello" * 1000
    assert await _read(b"", "gzip", 100) == b""  # no body at all (a 304 with the header): nothing to complain about


async def test_gzip_bomb_stops_at_the_limit_without_inflating_it():
    bomb = gzip.compress(b"\0" * 50_000_000)  # ~50 KB on the wire, 50 MB inflated
    assert len(bomb) < 100_000
    with pytest.raises(bounded.TooLarge):
        await _read(bomb, "gzip", 5_000_000)


async def test_stacked_or_unknown_encodings_are_refused():
    twice = gzip.compress(gzip.compress(b"\0" * 1_000_000))
    with pytest.raises(bounded.BadEncoding):
        await _read(twice, "gzip, gzip", 5_000_000)
    with pytest.raises(bounded.BadEncoding):
        await _read(b"x", "br", 100)
    with pytest.raises(bounded.BadEncoding):
        await _read(b"not gzip at all", "gzip", 100)


async def test_truncate_peeks_only():
    with pytest.raises(bounded.TooLarge):  # without truncate it is an error
        await _read(b"a" * 50_000, None, 4096)
    c, s = await _get(b"a" * 50_000, None)
    async with c, s as resp:
        assert await bounded.read_limited(resp, 4096, truncate=True) == b"a" * 4096


async def test_download_caps_a_gzip_bomb_and_asks_for_gzip_only():
    """news.download (feeds, logos, KEV/EUVD, CSAF, NVD, endoflife.date) uses the bounded reader."""
    seen = {}
    bomb = gzip.compress(b"<rss>" + b"\0" * 20_000_000)

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ae"] = request.headers.get("accept-encoding")

        async def body():
            yield bomb

        return httpx.Response(200, content=body(), headers={"content-encoding": "gzip"})

    with pytest.raises(news.NewsError) as exc:
        await news.download("https://feed.example/x", proxy=None, limit=1_000_000, transport=httpx.MockTransport(handler))
    assert exc.value.category == "too_large"
    assert seen["ae"] == "gzip, deflate"
