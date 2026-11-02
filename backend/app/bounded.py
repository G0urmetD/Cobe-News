"""Reading a response body from a server Cobe News does not control, with a hard size limit that also holds for compressed
answers: httpx inflates a whole network chunk at once and chains stacked encodings ("gzip, gzip") without an output
bound – 661 bytes became 315 MB before any size check could run. Here the raw bytes are read and inflated by our own
decompressor with a cap per step; only identity or a single gzip/deflate layer is accepted.
"""

import zlib
from collections.abc import AsyncIterator

import httpx

# what to ask for: one layer we can inflate with a bound (no br/zstd – httpx would inflate those unbounded)
ACCEPT_ENCODING = "gzip, deflate"


class TooLarge(Exception):
    pass


class BadEncoding(Exception):
    pass


def _encodings(resp: httpx.Response) -> list[str]:
    raw = resp.headers.get("content-encoding", "").lower()
    return [e.strip() for e in raw.split(",") if e.strip() and e.strip() != "identity"]


async def iter_limited(resp: httpx.Response, limit: int, chunk_size: int | None = None) -> AsyncIterator[bytes]:
    """The decoded body in pieces, never more than `limit` bytes in total (TooLarge beyond). Stacked or unknown
    content encodings raise BadEncoding instead of being inflated."""
    if hasattr(resp, "_content"):  # already in memory (a response built from bytes, e.g. in tests): nothing to inflate here
        if len(resp.content) > limit:
            raise TooLarge
        if resp.content:
            yield resp.content
        return
    enc = _encodings(resp)
    if len(enc) > 1 or (enc and enc[0] not in ("gzip", "x-gzip", "deflate")):
        raise BadEncoding(",".join(enc)[:40])
    d = zlib.decompressobj(47) if enc else None  # 47: zlib or gzip header, detected
    total = 0
    compressed = False
    try:
        async for raw in resp.aiter_raw(chunk_size):
            compressed = compressed or bool(raw)
            if d is None:
                out = raw
            else:
                # at most one byte past the limit is ever inflated; more waiting (unconsumed_tail) means past it
                out = d.decompress(raw, limit + 1 - total)
            if total + len(out) > limit:
                if limit > total:
                    yield out[: limit - total]  # up to the limit – a caller that only peeks keeps this much
                raise TooLarge
            total += len(out)
            if out:
                yield out
        if d is not None:
            out = d.flush(limit + 1 - total)
            total += len(out)
            if total > limit:
                raise TooLarge
            if out:
                yield out
            if compressed and not d.eof:
                # the compressed stream ended early (a cut connection, a truncated answer): not the whole body
                raise BadEncoding("truncated")
    except zlib.error as exc:
        raise BadEncoding("corrupt") from exc


async def read_limited(resp: httpx.Response, limit: int, *, truncate: bool = False) -> bytes:
    """The whole body up to `limit` bytes. truncate=True: stop quietly at the limit (an error text we only peek at)."""
    buf = bytearray()
    try:
        async for chunk in iter_limited(resp, limit):
            buf += chunk
    except TooLarge:
        if not truncate:
            raise
    return bytes(buf[:limit])
