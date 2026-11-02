"""Dringlichkeit: one number from 0 to 100 per finding (a vulnerability × an installed version of a followed product).

No model, no learning: a sum of fixed points, each factor shown in the breakdown ("KEV +30, EPSS 97 % +20, eure Version
betroffen +25 …"), then kept between 0 and 100. The weights live here and nowhere else – the handbook explains them
(docs/handbuch/*/03-vendor-news.md#dringlichkeit) and tests/test_vendor_score.py pins them.

    score = clamp(0, 100, severity + epss + exploited + version + no_fix + age [+ public_exploit])

- severity: the CVSS score's band (else the severity given): critical 35 · high 25 · medium 12 · low 4 · none 0
- epss: FIRST EPSS percentile: ≥ 95 % → 20 · ≥ 80 % → 10 · ≥ 50 % → 5 · below / unknown 0
- exploited: in CISA KEV → 30 · otherwise known as exploited (vendor, ENISA EUVD) → 25 · else 0
- version: the verdict for the own version: affected +25 · possibly affected / no version given +5 · cloud service 0 ·
  "unklare Altdaten" −50 · not affected −70 (whatever else it has, a not affected version stays below "Bald")
- no_fix: affected or possibly affected, and no fixed version known → +5
- age: published within 7 days → +10 · within 30 days → +5 · older 0
- public_exploit: reserved (+15) – the data source is not approved yet, so it never counts

Levels (the colours of the overview): ≥ 60 "now" (Sofort, red) · ≥ 35 "soon" (Bald, amber) · below "watch" (Beobachten).

Computed on the server only (the API, the UI and later rules see the same number), from what the cached product view
already holds – no query of its own. `apply` stores it on the view's findings once per day (the age moves on)."""

from __future__ import annotations

from datetime import UTC, date, datetime

SEVERITY = {"critical": 35, "high": 25, "medium": 12, "low": 4, "info": 0}
EPSS = ((0.95, 20), (0.80, 10), (0.50, 5))  # percentile from → points (the first that applies)
KEV = 30
EXPLOITED = 25  # known as exploited, but not (yet) in CISA KEV: the vendor's advisory, ENISA EUVD
VERSION = {"affected": 25, "possible": 5, "unversioned": 5, "service": 0, "stale": -50, "not_affected": -70}
NO_FIX = 5
AGE = ((7, 10), (30, 5))  # published within days → points
PUBLIC_EXPLOIT = 15  # reserved: "öffentlicher Exploit bekannt" – no approved source yet, never applied
USE_PUBLIC_EXPLOIT = False
LEVELS = ((60, "now"), (35, "soon"))  # from → level; below: "watch"
MIN, MAX = 0, 100


def band(cvss: float | None, severity: str | None) -> str:
    """The severity band: from the CVSS score when there is one (CVSS v3 bands), else the severity given."""
    if cvss is not None and cvss > 0:
        return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
    return severity if severity in SEVERITY else "info"


def level(value: int) -> str:
    for start, name in LEVELS:
        if value >= start:
            return name
    return "watch"


def _epss_points(percentile: float | None) -> int:
    if percentile is None:
        return 0
    for start, pts in EPSS:
        if percentile >= start:
            return pts
    return 0


def _age_days(published: str | None, today: date) -> int | None:
    if not published:
        return None
    try:
        d = datetime.fromisoformat(str(published).replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=UTC)
    return max(0, (today - d.astimezone(UTC).date()).days)


def _age_points(days: int | None) -> int:
    if days is None:
        return 0
    for within, pts in AGE:
        if days <= within:
            return pts
    return 0


def score(
    *,
    cvss: float | None,
    severity: str | None,
    epss_percentile: float | None,
    kev: bool,
    exploited: bool,
    status: str,
    fixed: bool,
    published: str | None,
    today: date,
    public_exploit: bool | None = None,
) -> dict:
    """{"value": 0–100, "level": now | soon | watch, "raw": the sum before clamping, "parts": [...]} – each part
    {"factor", "points", …what it was computed from}. Parts without points are left out, except the own version
    (always said: it is what the number is about)."""
    parts: list[dict] = []
    b = band(cvss, severity)
    parts.append({"factor": "severity", "points": SEVERITY[b], "band": b, "cvss": cvss})
    pts = _epss_points(epss_percentile)
    parts.append({"factor": "epss", "points": pts, "percentile": epss_percentile})
    if kev:
        parts.append({"factor": "kev", "points": KEV})
    elif exploited:
        parts.append({"factor": "exploited", "points": EXPLOITED})
    parts.append({"factor": "version", "points": VERSION.get(status, 0), "status": status})
    if status in ("affected", "possible", "unversioned") and not fixed:
        parts.append({"factor": "no_fix", "points": NO_FIX})
    days = _age_days(published, today)
    parts.append({"factor": "age", "points": _age_points(days), "days": days})
    if USE_PUBLIC_EXPLOIT and public_exploit:  # pragma: no cover - the slot is reserved, never switched on yet
        parts.append({"factor": "public_exploit", "points": PUBLIC_EXPLOIT})
    raw = sum(p["points"] for p in parts)
    value = max(MIN, min(MAX, raw))
    shown = [p for p in parts if p["points"] or p["factor"] == "version"]
    return {"value": value, "level": level(value), "raw": raw, "parts": shown}


def of_finding(f: dict, today: date) -> dict:
    """The finding's number: the highest over its version rows (each row: its own verdict and fixed version), with the
    breakdown of that row. Each row gets its `score` (the value alone)."""
    epss = f.get("epss") or {}
    common = {
        "cvss": f.get("cvss"),
        "severity": f.get("severity"),
        "epss_percentile": epss.get("percentile"),
        "kev": bool(f.get("kev")),
        "exploited": bool(f.get("exploited")),
        "published": f.get("published_at"),
        "today": today,
    }
    best: dict | None = None
    best_row: dict | None = None
    for row in f.get("versions") or []:
        s = score(**common, status=row.get("status") or "not_affected", fixed=bool(row.get("fixed")))
        row["score"] = s["value"]
        if best is None or s["value"] > best["value"] or (s["value"] == best["value"] and s["raw"] > best["raw"]):
            best, best_row = s, row
    if best is None:  # no version rows (cannot happen for a stored finding – kept total)
        best = score(**common, status=f.get("status") or "not_affected", fixed=False)
    out = dict(best)
    if best_row is not None:
        out["version"] = best_row.get("version")
    return out


def apply(view: dict, today: date | None = None) -> None:
    """The number on every finding of a cached product view – once per view and day (`view["_score_day"]`), as the
    view's summary is computed once. Synchronous, no await: two requests never see a half-scored view."""
    today = today or datetime.now(UTC).date()
    if view.get("_score_day") == today:
        return
    for f in view.get("findings") or []:
        f["score"] = of_finding(f, today)
    view["_score_day"] = today
    view.pop("_score_top", None)


def top(view: dict) -> dict | None:
    """The product's number for its card: its most urgent finding (value, level, breakdown, which finding) – None when
    it has no finding. After `apply`."""
    if "_score_top" in view:
        return view["_score_top"]
    best = None
    for f in view.get("findings") or []:
        s = f.get("score")
        if s and (best is None or s["value"] > best[0]["value"] or (s["value"] == best[0]["value"] and s["raw"] > best[0]["raw"])):
            best = (s, f)
    out = {**best[0], "finding": best[1]["id"], "ident": best[1]["ident"]} if best else None
    view["_score_top"] = out
    return out
