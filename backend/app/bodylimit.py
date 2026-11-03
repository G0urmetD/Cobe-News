"""The request body limit of the app – a second line behind nginx's client_max_body_size (1 MB), for a request that
reaches the app's own port or comes through a proxy of one's own (TLS_MODE=external).

Pure ASGI (no buffering): a Content-Length above the limit is answered 413 before the route runs; a body without one
(Transfer-Encoding: chunked) is counted while the route reads it – the moment it passes the limit the answer is 413 and
the route sees the client gone (http.disconnect); whatever it still answers is dropped – and a route that reads the
raw body (Starlette raises ClientDisconnect then) ends quietly with that 413, no traceback. No endpoint takes more than a
few kilobytes (there is no upload: backups are made and restored on the host – docs/BETRIEB.md) – one limit for all,
MAX_BODY_BYTES (default 1 MiB). Inside the app's guard (main.py): the 413 carries the same security headers as every
answer and is in the access log."""

import json

from starlette.requests import ClientDisconnect
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT = 1024 * 1024  # 1 MiB – what nginx lets through (client_max_body_size 1m)


def _refusal(limit: int) -> tuple[dict, bytes]:
    body = json.dumps({"detail": {"code": "body_too_large", "limit": limit}}).encode()
    start = {
        "type": "http.response.start",
        "status": 413,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")],
    }
    return start, body


class BodyLimit:
    def __init__(self, app: ASGIApp, limit: int = DEFAULT) -> None:
        self.app = app
        self.limit = limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit
        length = None
        for k, v in scope.get("headers") or ():
            if k == b"content-length":
                try:
                    length = int(v)
                except ValueError:
                    length = limit + 1  # not a number: nothing to trust (the server refuses it before this anyway)
                break
        if length is not None and length > limit:
            await self._refuse(send, limit)
            return

        seen = 0
        state = {"started": False, "refused": False}

        async def guarded_send(message: Message) -> None:
            if state["refused"]:
                return  # the 413 went out already – the route's own answer is dropped
            if message["type"] == "http.response.start":
                state["started"] = True
            await send(message)

        async def counted_receive() -> Message:
            nonlocal seen
            if state["refused"]:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body") or b"")
                if seen > limit:
                    if not state["started"]:
                        await self._refuse(send, limit)
                    state["refused"] = True
                    return {"type": "http.disconnect"}
            return message

        try:
            await self.app(scope, counted_receive, guarded_send)
        except ClientDisconnect:
            if not state["refused"]:
                raise  # the client really went – not ours to hide
            # the route read on after the refusal: the 413 that went out is the answer
            return

    @staticmethod
    async def _refuse(send: Send, limit: int) -> None:
        start, body = _refusal(limit)
        await send(start)
        await send({"type": "http.response.body", "body": body, "more_body": False})
