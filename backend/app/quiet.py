"""Quiet hours, urgency and collected delivery of the personal notifications (app/personal.py) – pure functions, the
round asks them once per person and round.

- **Quiet hours** (off by default): a daily window in the person's time zone (18:00–08:00 runs over midnight), plus
  Saturday and Sunday whole if chosen. Meanwhile normal messages wait; when the window ends, everything that waited goes
  out as one message per way (the round's digest).
- **Urgent** passes at once, also in the quiet hours: what the person chose of BITS – severity critical, CISA KEV
  (also "actively exploited"), an own version affected now by an advisory change, a watched CVE. An event's marks are
  set once, when it is queued (person_deliveries.marks); the person's choice is applied each round.
- **Collected** per way (off by default): "at HH:MM" – the normal messages of that way wait for the next HH:MM and go
  out together then (urgent ones still at once).
- **Time zones and summer time**: local wall time through zoneinfo (the IANA database of the system). A window is
  decided by the local time of day, so it follows the clock across a change. A collecting time that does not exist on
  the day the clocks go forward (02:30) is the first moment after the gap; one that exists twice when they go back is
  its first occurrence – once a day, never twice.
"""

from datetime import UTC, date, datetime, time, timedelta
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DEFAULT_TZ = "Europe/Berlin"
URGENT = ("critical", "kev", "affected", "watch")
BITS = {"critical": 1, "kev": 2, "affected": 4, "watch": 8}
DEFAULT_URGENT = URGENT
WAYS = ("email", "desktop", "teams")


@lru_cache(maxsize=256)
def _zone(name: str) -> ZoneInfo | None:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def valid_tz(name: str) -> bool:
    return bool(name) and len(name) <= 64 and _zone(name) is not None


def zone(name: str | None) -> ZoneInfo:
    """The person's zone – an unknown name (or none) is Europe/Berlin."""
    return _zone(name or DEFAULT_TZ) or _zone(DEFAULT_TZ) or ZoneInfo("UTC")


def hm(value: str | None, default: str = "08:00") -> time:
    """ "HH:MM" → time (a broken value: the default)."""
    for v in (value, default):
        try:
            h, m = str(v).split(":")
            return time(int(h), int(m))
        except (TypeError, ValueError):
            continue
    return time(8, 0)


def valid_hm(value: str) -> bool:
    try:
        h, m = value.split(":")
        return len(h) == 2 and len(m) == 2 and 0 <= int(h) < 24 and 0 <= int(m) < 60
    except (AttributeError, ValueError):
        return False


def mask(schedule: dict | None) -> int:
    """The bits of the urgent kinds the person chose (none chosen yet: the defaults)."""
    s = schedule or {}
    chosen = s.get("urgent")
    if not isinstance(chosen, list):
        chosen = DEFAULT_URGENT
    return sum(BITS[k] for k in set(chosen) if k in BITS)


def is_quiet(schedule: dict | None, now: datetime) -> bool:
    """Inside the person's quiet hours at `now` (an aware datetime)."""
    s = schedule or {}
    if not s.get("quiet"):
        return False
    local = now.astimezone(zone(s.get("tz")))
    if s.get("weekends") and local.weekday() >= 5:
        return True
    start, end = hm(s.get("from"), "18:00"), hm(s.get("to"), "08:00")
    cur = local.time().replace(second=0, microsecond=0, tzinfo=None)
    if start == end:
        return False
    if start < end:
        return start <= cur < end
    return cur >= start or cur < end


def _at(day: date, t: time, z: ZoneInfo) -> datetime:
    """Local `t` on `day` as UTC – in the gap of a change to summer time the first moment after it (fold 0: the offset
    before the change), when the clocks go back the first occurrence."""
    return datetime.combine(day, t, tzinfo=z).astimezone(UTC)


def last_slot(at: str | None, tz: str | None, now: datetime) -> datetime:
    """The newest daily time HH:MM (local) at or before `now`, as UTC."""
    z, t = zone(tz), hm(at)
    today = now.astimezone(z).date()
    for back in range(3):
        slot = _at(today - timedelta(days=back), t, z)
        if slot <= now:
            return slot
    return _at(today - timedelta(days=3), t, z)  # unreachable: a day has at most 25 hours


def last_weekly(weekday: int, at: str | None, tz: str | None, now: datetime) -> datetime:
    """The newest weekly time (weekday 0 = Monday, HH:MM local) at or before `now`, as UTC."""
    z, t = zone(tz), hm(at)
    today = now.astimezone(z).date()
    for back in range(9):
        d = today - timedelta(days=back)
        if d.weekday() == weekday % 7:
            slot = _at(d, t, z)
            if slot <= now:
                return slot
    return _at(today - timedelta(days=14), t, z)  # unreachable


def week_of(slot: datetime, tz: str | None) -> str:
    """ISO week of the slot's local date – "2026-W45": one review per team, person and week."""
    y, w, _ = slot.astimezone(zone(tz)).date().isocalendar()
    return f"{y}-W{w:02d}"


def active(schedule: dict | None) -> bool:
    """Whether anything of the schedule holds a message back (quiet hours or a collected way)."""
    s = schedule or {}
    return bool(s.get("quiet")) or any((s.get("daily") or {}).get(w) for w in WAYS)


def hold(schedule: dict | None, way: str, now: datetime) -> tuple[bool, datetime | None]:
    """(held, cutoff) for one person and way at `now`: held False – nothing waits. Held: urgent rows pass, the others
    only when queued at or before `cutoff` (None: none of them – the quiet hours)."""
    s = schedule or {}
    if is_quiet(s, now):
        return True, None
    daily = (s.get("daily") or {}).get(way)
    if daily:
        return True, last_slot(daily, s.get("tz"), now)
    return False, None


def clean(body: dict) -> dict:
    """The stored form of a schedule from the API (already validated)."""
    return {
        "quiet": bool(body.get("quiet")),
        "from": body.get("from") or "18:00",
        "to": body.get("to") or "08:00",
        "weekends": bool(body.get("weekends")),
        "tz": body.get("tz") or DEFAULT_TZ,
        "urgent": [k for k in URGENT if k in (DEFAULT_URGENT if body.get("urgent") is None else body["urgent"])],
        "daily": {w: (body.get("daily") or {}).get(w) or None for w in WAYS},
    }


def out(schedule: dict | None) -> dict:
    """What the UI shows (defaults filled in)."""
    s = schedule or {}
    chosen = s.get("urgent")
    return {
        "quiet": bool(s.get("quiet")),
        "from": s.get("from") or "18:00",
        "to": s.get("to") or "08:00",
        "weekends": bool(s.get("weekends")),
        "tz": s.get("tz") or DEFAULT_TZ,
        "urgent": [k for k in URGENT if k in chosen] if isinstance(chosen, list) else list(DEFAULT_URGENT),
        "daily": {w: (s.get("daily") or {}).get(w) or None for w in WAYS},
    }


def marks_of(kind: str, severity: str, data: dict | None) -> int:
    """The urgency bits of an event – set when it is queued."""
    d = data or {}
    m = BITS["critical"] if severity == "critical" else 0
    if kind == "watch":
        m |= BITS["watch"]
        if d.get("what") == "kev":
            m |= BITS["kev"]
    elif kind == "vuln":
        if d.get("exploited") or d.get("now_exploited") or d.get("kev"):
            m |= BITS["kev"]
    elif kind == "change":
        if any(isinstance(x, dict) and x.get("f") == "kev" for x in d.get("diff") or []):
            m |= BITS["kev"]
        from app.advisory_changes import worse

        if any(isinstance(x, dict) and x.get("to") == "affected" and worse(x) for x in d.get("impact") or []):
            m |= BITS["affected"]
    return m
