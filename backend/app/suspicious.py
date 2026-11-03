"""Log lines for suspicious requests – throttled, so nobody can flood the log with them.

CSRF failures (main._guard): a write to /api/ without the CSRF token, or with the wrong one – a browser of this app
never sends one (it always carries the token), another site's page or a script does. One line per source (an IPv4
address, an IPv6 /64 – bruteforce.source_key) and minute at most, and LINES_PER_MINUTE across all sources; what was held
back is counted and named in the next line. No audit entry: there is nobody signed in to name, and it is not an action
on anything. Never a token or cookie value – only whether each was there and whether they matched."""

import logging
import time

from app.auth import bruteforce

log = logging.getLogger("cobe_news.security")

EVERY = 60.0  # s – one line per source at most
LINES_PER_MINUTE = 30  # … and this many across all sources
MAX_SOURCES = 4096  # sources remembered – beyond that the oldest are forgotten


class Throttle:
    """`hit(key)`: None – held back (counted); else the number held back for this key since its last line."""

    def __init__(self, every: float = EVERY, total: int = LINES_PER_MINUTE, max_keys: int = MAX_SOURCES) -> None:
        self.every, self.total, self.max_keys = every, total, max_keys
        self._last: dict[str, tuple[float, int]] = {}  # key → (time of its last line, held back since)
        self._window: list[float] = []  # times of the lines of the last `every` seconds, all keys

    def hit(self, key: str, now: float | None = None) -> int | None:
        t = time.monotonic() if now is None else now
        last, held = self._last.get(key, (-1e18, 0))
        self._window = [x for x in self._window if t - x < self.every]
        if t - last < self.every or len(self._window) >= self.total:
            self._remember(key, last, held + 1)
            return None
        self._window.append(t)
        self._remember(key, t, 0)
        return held

    def _remember(self, key: str, at: float, held: int) -> None:
        self._last.pop(key, None)
        self._last[key] = (at, held)  # newest last – the oldest go first when there are too many
        while len(self._last) > self.max_keys:
            self._last.pop(next(iter(self._last)))

    def reset(self) -> None:
        self._last.clear()
        self._window.clear()


_csrf = Throttle()


def csrf_failed(method: str, path: str, ip: str, *, cookie: bool, header: bool) -> bool:
    """A refused write (403 csrf_failed) – logged when the throttle lets it through (True)."""
    src = bruteforce.source_key(ip)
    held = _csrf.hit(src)
    if held is None:
        return False
    why = "token cookie missing" if not cookie else "token header missing" if not header else "token mismatch"
    shown = "".join(c if c.isprintable() else "?" for c in path[:200])  # a %0A in the path cannot start a line of its own
    log.warning("csrf check failed: %s %s from %s (%s)%s", method, shown, src, why, f" – {held} more from this source since the last line" if held else "")
    return True


def reset() -> None:
    _csrf.reset()
