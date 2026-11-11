"""Vendor News API. Everybody signed in sees the catalogue, the followed products and their findings; admins decide what
the installation follows (products, versions, notes), add products by CPE, and change the settings."""

import asyncio
import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request, Response
from pydantic import ConfigDict, Field, field_validator
from sqlalchemy import and_, select, update

from app import advisory_changes as changes_svc
from app import advisory_cleanup, audit, catalog_check, exploits, finding_confirm, plaintext, reader, teams
from app import catalog_care as care
from app import vendor as svc
from app import vendor_catalog as catalog
from app import vendor_score as score_svc
from app import vendor_sources as src
from app import version_input, vmware_builds
from app import settings as settings_store
from app import systems
from app.crypto import encrypt_str
from app.deps import Admin, Db, NoNul, Reader, api_error
from app.models import VendorFetch, VendorFollow, VendorVersion
from app.news import NewsError
from app.vendor_match import ORDER

router = APIRouter(prefix="/api", tags=["vendor"])
MAX_VERSIONS = 30
CPE_TTL = 3600.0
_cpe_cache: dict[str, tuple[float, list]] = {}
_last_cpe_search = [-1e9]
_last_catalog = [-1e9]


class _M(NoNul):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def _product_out(p: dict) -> dict:
    scheme = p.get("scheme") or "generic"
    return {
        "key": p["key"],
        "label": p.get("label") or p["key"],
        "vendor": p.get("vendor") or "",
        "category": p.get("category") or "other",
        "scheme": scheme,
        "example": version_input.example_for(p),
        "cloud": bool(p.get("cloud")) or scheme == "cloud",
        "cpes": list(p.get("cpes") or []),
        "advisory": p.get("adv"),
        "eol": bool(p.get("eol")),
        "aliases": list(p.get("aliases") or []),
        "hint": p.get("hint"),
        "version_cmd": p.get("version_cmd"),
        # where the command comes from: endoflife.date's data is shown as such ("laut endoflife.date") – a hint, not ours
        "version_cmd_from": p.get("version_cmd_from") or ("eol" if p.get("version_cmd") and str(p.get("source") or "").startswith("eol") else "catalog"),
        "version_where": p.get("where"),
        # vCenter, ESXi: the four-part version and builds are taken too (looked up and stored as the release)
        "builds": vmware_builds.has_table(p["key"]) and (p.get("scheme") == "vmware"),
        "custom": p.get("source") == "custom",
    }


@router.get("/vendor/catalog")
async def get_catalog(user: Reader, db: Db) -> dict:
    """The whole catalogue (about 650 products – searched in the browser) with what is followed."""
    cat = catalog.load()
    fs = await svc.follows(db, enabled_only=False)
    vers = await svc.versions_of(db, [f.id for f in fs])
    followed = {f.product: {"enabled": f.enabled, "versions": len(vers.get(f.id, []))} for f in fs}
    products = [_product_out(p) for p in cat["products"]]
    # the vendor as the notification rules' "Systeme" know it: one per brand, whatever the spelling ("VMware",
    # "Broadcom (VMware)") – the rule editor groups the products by it (app/systems.py)
    ix = systems.index()
    for p in products:
        if (gid := ix.vendor_of.get(p["key"])) is not None:
            p["vendor_group"], p["vendor_group_name"] = gid, ix.vendors[gid]["name"]
    for f in fs:
        if f.custom:
            products.append(_product_out(catalog.custom_product({**f.custom, "key": f.product})))
    counts = {c: {"total": 0, "followed": 0} for c in catalog.CATEGORIES}
    for p in products:
        c = counts.setdefault(p["category"], {"total": 0, "followed": 0})
        c["total"] += 1
        c["followed"] += bool(followed.get(p["key"], {}).get("enabled"))
    return {"generated_at": cat.get("generated_at"), "catalog_version": catalog.catalog_version(), "categories": counts, "products": products, "followed": followed}


@router.get("/vendor/catalog/meta")
async def catalog_meta(user: Reader, response: Response) -> dict:
    """What the catalogue data says beyond the products: its version, the categories in display order (icon, label in
    de and en) and the texts products refer to (hints, where the version is read) – they come with the catalogue data
    (app/catalog), not with the UI, so a newer catalogue brings its own texts. Changes only with the image."""
    d = catalog.DATA
    response.headers["Cache-Control"] = "private, max-age=3600"
    return {
        "catalog_version": d.version,
        "categories": [{"key": c["key"], "icon": c["icon"], "label": {"de": c["de"], "en": c["en"]}} for c in d.categories],
        "texts": d.texts,
    }


def _check_extra(product: dict, c: version_input.Checked) -> dict:
    """What explains a refused version: the catalogue hint (key and text), the product it belongs to, the known lines."""
    out: dict = {}
    if c.reason in vmware_builds.HINTS:
        out["hint"] = vmware_builds.HINTS[c.reason]
    elif c.hint and (text := catalog.DATA.texts["hints"].get(c.hint)):
        out["hint"] = text
        out["hint_key"] = c.hint
    if c.to:
        other = catalog.product(c.to) or {}
        out |= {"to": c.to, "to_label": other.get("label") or c.to}
    if c.lines:
        out["lines"] = list(c.lines)
    return out


def _version_out(v: VendorVersion, product: dict, rv: care.Review | None = None) -> dict:
    c = version_input.check(product, v.version)
    ok, reason = c.ok, c.reason
    short = ok and svc.short_version(product, v.version)
    out = {"id": str(v.id), "version": v.version, "label": v.label, "count": v.count, "valid": ok, "invalid_reason": reason or None, "short": short, "updated_at": _iso(v.updated_at)}
    eff = version_input.effective(product, v.version)
    if eff and eff != v.version and " ".join(eff.split()) != " ".join(v.version.split()):
        out["effective"] = eff  # stored before a rule existed ("2019 CU15"): compared as 15.2.1748 – the card says so
    if not ok:
        out |= {f"invalid_{k}": x for k, x in _check_extra(product, c).items()}
    if rv is not None:
        out["review"] = rv.of(v, product)  # "Versionen prüfen": when last confirmed, by whom, due (app/catalog_care.py)
    return out


def _reading_out(rd: reader.VendorReading | None, key: str, fs: list[dict], counts: dict) -> dict:
    """The viewer's read state and mutes of a product (app/reader.py): unread findings, muted until when, and whether
    an exploited vulnerability affects it while it is muted (the list shows it with a badge, also when muted ones are hidden)."""
    if rd is None:
        return {}
    until = rd.mutes.products.get(key)
    return {
        "unread": rd.count(key, fs),
        "unread_all": rd.count_all(key, fs),  # with the muted ones – "Alle N als gelesen" while muted ones are shown
        "muted": {"until": until.isoformat()} if until else None,
        "muted_kev": bool(until) and bool(counts.get("exploited_affected")),
    }


async def _overview_row(
    db,
    f: VendorFollow,
    vs: list[VendorVersion],
    kev,
    euvd,
    rv: care.Review | None = None,
    may: set[str] | None = None,
    rd: reader.VendorReading | None = None,
    deadline: float | None = None,
) -> dict:
    view = await svc.product_view(db, f, vs, kev=kev, euvd=euvd, deadline=deadline)
    score_svc.apply(view)  # Dringlichkeit: once per view and day (app/vendor_score.py)
    p = view["product"]
    fs = view["findings"]
    # confirmed findings (app/finding_confirm.py) are handled: not in the card's numbers, its state, its worst lines
    skip = rd.confirms.skip(f.product, fs) if rd is not None and rd.confirms else frozenset()
    summ = svc.summary(view, vs, skip)
    rel = [{"version_id": str(v.id), **(svc.release_info(p, v.version) or {})} for v in vs]
    for r in rel:
        r.pop("lines", None)
    top, counts = _open_counts(view, skip)
    done = [x for x in fs if x["id"] in skip and x["status"] in reader.RELEVANT]

    def brief(x: dict) -> dict:
        return {k: x[k] for k in ("id", "ident", "title", "headline", "severity", "exploited", "status", "published_at", "cvss")} | {"score": _brief(x.get("score")), "tlp": x.get("tlp")}

    return {
        "product": _product_out(p),
        "follow": {"enabled": f.enabled, "note": f.note, "tags": f.tags or [], "created_at": _iso(f.created_at)},
        "versions": [_version_out(v, p, rv) for v in vs],
        "can_confirm": may is None or f.product in may,
        "summary": summ,
        "releases": rel,
        "counts": counts,
        "urgency": svc.urgency(counts, rel),
        # Dringlichkeit as one number: the product's most urgent finding, with its breakdown (app/vendor_score.py)
        "score": score_svc.top(view, skip),
        # the most relevant first, in the drawer's order (affected before possibly, exploited, CVSS) – not the newest:
        # a "possibly affected" one must never stand at the top of a card whose versions have affected ones
        "latest": [brief(x) | ({"unread": rd.unread(f.product, x["id"]), "muted": rd.muted(f.product, x)} if rd is not None else {}) for x in top[:3]],
        # the confirmed ones of the kinds the card shows – how many, and the worst three ("Mit Bestätigten")
        "confirmed": len(done),
        "latest_confirmed": [brief(x) | {"confirmed": finding_confirm.out(rd.confirms.of(f.product, x))} for x in done[:3]] if rd is not None and rd.confirms else [],
        "same_data": [],
    } | _reading_out(rd, f.product, fs, counts)


def _brief(s: dict | None) -> dict | None:
    return {"value": s["value"], "level": s["level"]} if s else None


def _open_counts(view: dict, skip: frozenset[str]) -> tuple[list[dict], dict]:
    """The card's findings and numbers without the confirmed ones – kept with the view when none is confirmed."""
    if skip:
        return _counts([x for x in view["findings"] if x["id"] not in skip])
    top, counts = view.get("_counts") or _counts(view["findings"])
    view["_counts"] = (top, counts)  # once per view
    return top, counts


def _counts(fs: list[dict]) -> tuple[list[dict], dict]:
    top = [f for f in fs if f["status"] in ("affected", "possible", "service", "unversioned")]
    hit = [f for f in fs if f["status"] == "affected"]
    counts = {
        "affected": len(hit),
        "possible": sum(1 for x in fs if x["status"] == "possible"),
        "service": sum(1 for x in fs if x["status"] == "service"),
        "unversioned": sum(1 for x in fs if x["status"] == "unversioned"),
        "stale": sum(1 for x in fs if x["status"] == "stale"),  # "unklare Altdaten": shown folded, never counted
        "critical": sum(1 for x in top if x["severity"] == "critical"),
        "exploited": sum(1 for x in top if x["exploited"]),
        # what makes a card red: critical or exploited vulnerabilities that affect a version (not "possibly")
        "critical_affected": sum(1 for x in hit if x["severity"] == "critical"),
        "exploited_affected": sum(1 for x in hit if x["exploited"]),
    }
    return top, counts


def _same_data(rows: list[dict]) -> None:
    """Followed products the NVD lists under the same CPE (Wazuh Agent and Wazuh Manager added by the same CPE, PAN-OS
    and Panorama): its CVEs appear on both cards – each card names the others."""
    cpes = {r["product"]["key"]: {c.replace("\\", "") for c in r["product"]["cpes"]} for r in rows}
    for r in rows:
        mine = cpes[r["product"]["key"]]
        r["same_data"] = [o["product"]["label"] for o in rows if o is not r and mine & cpes[o["product"]["key"]]]


def _no_single():  # noqa: ANN202
    """Not the single lookups (one vendor_fetch row per CVE: story details, cvelistV5, OSV) – by the key's index."""
    return and_(*(~VendorFetch.key.startswith(p, autoescape=True) for p in svc.PER_CVE))


async def _status(db) -> dict:
    cfg = await svc.config(db)
    states = list(await db.scalars(select(VendorFetch).where(_no_single())))
    # only the queries the round still asks: the error of a product no longer followed is no error of a source now
    active = await svc.active_keys(db)
    errors = [s for s in states if s.error and s.key in active]
    fetched = any(s.last_ok_at for s in states)
    tried = [s for s in states if s.key in active and s.last_fetch_at]
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "last_ok_at": _iso(max((s.last_ok_at for s in states if s.last_ok_at), default=None)),
        "errors": len(errors),
        "fetched": fetched,
        # nothing has ever answered and every source asked so far failed: not "Erster Abruf läuft" (that never ended)
        "failed": not fetched and bool(tried) and all(s.error for s in tried),
    }


@router.get("/vendor/overview")
async def overview(user: Reader, db: Db, scope: Literal["all", "team"] = "all") -> dict:
    """The followed products; `scope=team` ("Mein Team"): only those of the viewer's teams – while Teams is off the
    parameter changes nothing (`team_scope` false in the answer). `total`: how many products are followed in all (the
    number on the tab, also with "Mein Team" – the page needs no second, full answer for it)."""
    fs = await svc.follows(db)
    total = len(fs)
    mine = await teams.my_products(db, user.id) if scope == "team" else None
    if mine is not None:
        fs = [f for f in fs if f.product in mine]
    rows: list[dict] = []
    if fs:  # "Mein Team" without products: neither the KEV list nor the EUVD CVEs are read
        vers = await svc.versions_of(db, [f.id for f in fs])
        kev, euvd = await svc.kev_index(db), await svc.euvd_cves(db)
        rv = await care.review_ctx(db, [v for x in vers.values() for v in x])
        may = await care.confirmable(db, user)
        rd = await reader.vendor_reading(db, user, [f.product for f in fs])
        # after a change for all (KEV, EPSS, catalogue, settings): the previous views until the new ones are ready
        dl = svc.stale_deadline(svc.STALE_WAIT)
        rows = [await _overview_row(db, f, vers.get(f.id, []), kev, euvd, rv, may, rd, dl) for f in fs]
        _same_data(rows)
        changed = await changes_svc.recent_by_product(db, [f.product for f in fs])
        for r in rows:
            r["changed"] = changed.get(r["product"]["key"])  # revised advisories within the last days ("Geändert")
    # `now`: the load time – "Alle gelesen" marks what had arrived up to it (app/reader.py)
    return {"status": await _status(db), "items": rows, "team_scope": mine is not None, "total": total, "review_days": await care.review_days(db), "now": datetime.now(UTC).isoformat()}


@router.get("/vendor/badge")
async def badge(user: Reader, db: Db) -> dict:
    """The number on "Vendor News" in the sidebar (polled on every page): how many followed products a vulnerability
    affects, and whether an exploited one does (red) – from the same cached views as the overview, without its payload.
    Vendor News switched off: nothing (no red dot for a switched-off page). After a change for all the previous views
    count until the new ones are ready (product_view: polled on every page, it never waits seconds for them)."""
    if not (await svc.config(db)).get("enabled", True):
        return {"affected": 0, "exploited": False, "enabled": False}
    fs = await svc.follows(db)
    vers = await svc.versions_of(db, [f.id for f in fs])
    kev, euvd = await svc.kev_index(db), await svc.euvd_cves(db)
    affected = 0
    exploited = False
    dl = svc.stale_deadline(svc.STALE_WAIT)
    st = await finding_confirm.standing(db, [f.product for f in fs])  # confirmed findings count as handled
    for f in fs:
        view = await svc.product_view(db, f, vers.get(f.id, []), kev=kev, euvd=euvd, deadline=dl)
        _top, counts = _open_counts(view, st.skip(f.product, view["findings"]) if st else frozenset())
        affected += bool(counts["affected"])
        exploited = exploited or bool(counts["exploited_affected"])
    return {"affected": affected, "exploited": exploited, "enabled": True}


def _follow_target(f: VendorFollow) -> audit.Target:
    p = svc.product_of(f) or {}
    return audit.target("product", f.product, p.get("label") or (f.custom or {}).get("label") or f.product)


async def _follow(db, key: str) -> VendorFollow:
    f = await db.scalar(select(VendorFollow).where(VendorFollow.product == key))
    if f is None:
        raise api_error(404, "not_found")
    return f


def _catalog_product(key: str) -> dict:
    p = catalog.product(key)
    if p is None:
        raise api_error(404, "not_found")
    return p


DETAIL_PAGE = 100
DETAIL_MAX = 500


@router.get("/vendor/products/{key}")
async def product_detail(
    key: str,
    user: Reader,
    db: Db,
    all: bool = False,  # noqa: A002 - query name
    offset: Annotated[int, Query(ge=0, le=100000)] = 0,
    limit: Annotated[int, Query(ge=1, le=DETAIL_MAX)] = DETAIL_MAX,  # the drawer asks for pages of DETAIL_PAGE
    sort: Literal["relevance", "epss", "score"] = "relevance",
) -> dict:
    """One followed product with its findings, page by page (`offset`/`limit` over the list in the drawer's order:
    affected, possibly, …, unklare Altdaten, not affected) – `shown` says how many there are in all, `by_status` how many
    of each kind. The related stories come with the first page only."""
    if catalog.product(key) is None and key in catalog.REPLACED:
        key = catalog.REPLACED[key]  # a key merged into another product (an old link): the product it is now
    f = await db.scalar(select(VendorFollow).where(VendorFollow.product == key))
    if f is None:
        p = _catalog_product(key)
        return {"product": _product_out(p), "follow": None, "versions": [], "findings": [], "releases": svc.release_info(p, None), "news": await svc.related_news(db, p, [])}
    vs = (await svc.versions_of(db, [f.id])).get(f.id, [])
    view = await svc.product_view(db, f, vs)
    score_svc.apply(view)
    p = view["product"]
    fs = view["findings"]
    shown = fs if all else [x for x in fs if x["status"] != "not_affected"]
    if sort == "epss":
        # within each kind (the drawer's groups) the likeliest to be exploited first (EPSS), then as usual
        shown = sorted(shown, key=lambda x: (-ORDER[x["status"]], -((x.get("epss") or {}).get("score") or -1.0)))
    elif sort == "score":
        # within each kind the most urgent first (Dringlichkeit), then as usual
        shown = sorted(shown, key=lambda x: (-ORDER[x["status"]], -(x.get("score") or {}).get("value", -1)))
    cves = [c for x in fs if x["status"] != "not_affected" for c in x["cves"]][:60]
    by_status: dict[str, int] = {}
    for x in fs:
        by_status[x["status"]] = by_status.get(x["status"], 0) + 1
    rv = await care.review_ctx(db, vs)
    may = await care.confirmable(db, user)
    rd = await reader.vendor_reading(db, user, [key])
    page = await _with_changes(db, shown[offset : offset + limit])
    st = rd.confirms if rd.confirms is not None else finding_confirm.Standing()
    for x in page:
        x["unread"], x["muted"] = rd.unread(key, x["id"]), rd.muted(key, x)
        c, gone = st.of(key, x), st.lapsed(key, x["id"])
        x["confirmed"] = finding_confirm.out(c) if c else None
        x["confirm_lapsed"] = finding_confirm.lapsed_out(gone) if gone and not c else None
    skip = st.skip(key, fs) if st else frozenset()
    until = rd.mutes.products.get(key)
    return {
        "product": _product_out(p),
        "follow": {"enabled": f.enabled, "note": f.note, "tags": f.tags or [], "created_at": _iso(f.created_at)},
        "versions": [_version_out(v, p, rv) | {"release": svc.release_info(p, v.version)} for v in vs],
        "review_days": rv.days,
        "can_confirm": may is None or f.product in may,
        "releases": svc.release_info(p, None),
        "summary": svc.summary(view, vs, skip),
        "findings": page,
        "confirmed": sum(1 for x in fs if x["id"] in skip and x["status"] in reader.RELEVANT),
        "unread": rd.count(key, fs),
        "muted": {"until": until.isoformat()} if until else None,
        "now": datetime.now(UTC).isoformat(),
        "offset": offset,
        "limit": limit,
        "shown": len(shown),
        "by_status": by_status,
        "not_affected": by_status.get("not_affected", 0),
        "total": len(fs),
        "news": await svc.related_news(db, p, cves) if offset == 0 else [],
        # Katalog-Pflege: the catalogue entry of a followed product needs care (a CPE missing in the NVD …)
        "catalog_check": await catalog_check.of_product(db, key) if offset == 0 else None,
    }


async def _with_changes(db, fs: list[dict]) -> list[dict]:  # noqa: ANN001
    """The page's findings with their newest revision within advisory_changes.RECENT ("Geändert") – of the advisory or
    one of its CVE records. Copies: the findings belong to the cached view."""
    ids = {x["id"]: [x["id"], *(f"{a['source']}:{a['ident']}" for a in x.get("also") or [])] for x in fs}
    got = await changes_svc.latest(db, [i for v in ids.values() for i in v])
    out = []
    for x in fs:
        mine = [got[i] for i in ids[x["id"]] if i in got]
        out.append({**x, "changed": max(mine, key=lambda c: c["at"]) if mine else None})
    return out


@router.get("/vendor/products/{key}/changes")
async def product_changes(key: str, user: Reader, db: Db) -> dict:
    """The revisions of the advisories of one followed product (advisory_changes), newest first: what changed and what
    it means for the versions entered."""
    return {"changes": await changes_svc.of_product(db, key)}


# ---------------------------------------------------------------- Treffer bestätigen (app/finding_confirm.py)


class FindingIn(_M):
    product: str = Field(min_length=1, max_length=200)
    finding: str = Field(min_length=1, max_length=400)


class ConfirmIn(FindingIn):
    status: Literal["not_affected", "mitigated", "accepted"]
    note: str = Field(default="", max_length=finding_confirm.NOTE_MAX)


async def _confirmable_finding(db, user, product: str, finding: str) -> tuple[VendorFollow, dict]:  # noqa: ANN001
    """The followed product and the finding as the drawer shows it now – for someone who may confirm it: an admin, or
    (Teams on) a member of a team the product belongs to (catalog_care.confirmable, as "Versionen prüfen"); 403 else."""
    f = await _follow(db, product)
    may = await care.confirmable(db, user)
    if may is not None and f.product not in may:
        raise api_error(403, "forbidden")
    vs = (await svc.versions_of(db, [f.id])).get(f.id, [])
    view = await svc.product_view(db, f, vs)
    x = next((y for y in view["findings"] if y["id"] == finding), None)
    if x is None:
        raise api_error(404, "not_found")
    return f, x


@router.post("/vendor/findings/confirm")
async def confirm_finding(body: ConfirmIn, user: Reader, db: Db) -> dict:
    """"Bestätigen…": the finding assessed for everybody – it counts as handled and is not notified until it is undone or
    changes materially. Confirming again changes status and reason (and takes the finding as it is now)."""
    f, x = await _confirmable_finding(db, user, body.product, body.finding)
    if x["status"] not in reader.RELEVANT:
        raise api_error(422, "finding_not_open")  # not affected / unklare Altdaten: nothing to confirm
    note = plaintext.label(body.note)  # one line, no control or direction characters (as every typed label)
    if body.status in finding_confirm.NOTE_REQUIRED and not note:
        raise api_error(422, "note_required")
    before = await finding_confirm.current(db, f.product, x["id"])
    was = {"status": before.status, "note": before.note} if before is not None else None
    c = await finding_confirm.confirm(db, user, f.product, x, body.status, note)
    details = {"finding": x["id"], "ident": x["ident"], "status": body.status, "note": note} | ({"was": was} if was else {})
    audit.record(db, user, "vendor.finding_confirmed", _follow_target(f), details)
    await db.commit()
    finding_confirm.changed()  # after the commit: API v1's cached lists are made anew from what is stored
    return {"product": f.product, "finding": x["id"], "confirmed": finding_confirm.out(c)}


@router.post("/vendor/findings/unconfirm")
async def unconfirm_finding(body: FindingIn, user: Reader, db: Db) -> dict:
    """"Bestätigung aufheben": the finding counts and notifies again from now on (what was held back stays unsent)."""
    f = await _follow(db, body.product)
    may = await care.confirmable(db, user)
    if may is not None and f.product not in may:
        raise api_error(403, "forbidden")
    c = await finding_confirm.undo(db, user, f.product, body.finding)
    if c is None:
        raise api_error(404, "not_found")
    ident = body.finding.partition(":")[2] or body.finding
    audit.record(db, user, "vendor.finding_unconfirmed", _follow_target(f), {"finding": body.finding, "ident": ident, "status": c.status, "note": c.note})
    await db.commit()
    finding_confirm.changed()
    return {"product": f.product, "finding": body.finding, "confirmed": None}


# ---------------------------------------------------------------- follow, versions (admins)


class FollowIn(_M):
    """PATCH semantics for an existing follow: only the fields sent change (the catalogue switch sends `enabled` alone and
    must not wipe the note and the tags)."""

    enabled: bool = True
    note: str = Field(default="", max_length=500)
    tags: list[Annotated[str, Field(min_length=1, max_length=40)]] = Field(default_factory=list, max_length=10)


def _wake(request: Request) -> None:
    w = getattr(request.app.state, "vendor_wake", None)
    if w:
        w()


@router.put("/vendor/follows/{key}")
async def put_follow(key: str, body: FollowIn, request: Request, admin: Admin, db: Db) -> dict:
    f = await db.scalar(select(VendorFollow).where(VendorFollow.product == key))
    now = datetime.now(UTC)
    if f is None:
        p = _catalog_product(key)
        f = VendorFollow(product=key, enabled=body.enabled, note=body.note, tags=list(dict.fromkeys(body.tags)), created_at=now, updated_at=now)
        db.add(f)
        audit.record(db, admin, "catalog.followed", _follow_target(f), {"enabled": f.enabled, "tags": f.tags})
        await db.commit()
        await advisory_cleanup.on_follow(db, p)  # its queries start in full: what the cleanup removed comes back
        await svc.relink(db, p)
    else:
        switched_on = "enabled" in body.model_fields_set and body.enabled and not f.enabled
        if body.enabled and not f.enabled:
            # switched on again: what is found now is the baseline, not news – also for its versions (the events that
            # told the earlier notifications apart were pruned while it was off)
            f.baseline_at = None
            await db.execute(update(VendorVersion).where(VendorVersion.follow_id == f.id).values(baseline_at=None))
        sent = body.model_fields_set
        before = {"enabled": f.enabled, "note": f.note, "tags": list(f.tags or [])}
        if "enabled" in sent:
            f.enabled = body.enabled
        if "note" in sent:
            f.note = body.note
        if "tags" in sent:
            f.tags = list(dict.fromkeys(body.tags))
        if changes := audit.diff(before, {"enabled": f.enabled, "note": f.note, "tags": list(f.tags or [])}):
            audit.record(db, admin, "catalog.follow_changed", _follow_target(f), {"changes": changes})
        f.updated_at = now
        await db.commit()
        if switched_on and (p := svc.product_of(f)) is not None:
            await advisory_cleanup.on_follow(db, p)
    svc.bump([key])
    _wake(request)
    return {"ok": True}


@router.delete("/vendor/follows/{key}")
async def delete_follow(key: str, admin: Admin, db: Db) -> dict:
    f = await _follow(db, key)
    audit.record(db, admin, "catalog.unfollowed", _follow_target(f))
    await db.delete(f)  # its versions go with it
    await db.commit()
    svc.bump([key])
    return {"ok": True}


class CustomIn(_M):
    cpe: str = Field(min_length=5, max_length=200, pattern=r"^(cpe:2\.3:)?[aoh]:[^:\s]+:[^:\s]+$")
    label: str = Field(min_length=2, max_length=120)
    category: str = "other"

    @field_validator("category")
    @classmethod
    def _cat(cls, v: str) -> str:
        if v not in catalog.CATEGORIES:
            raise ValueError("unknown category")
        return v


@router.post("/vendor/custom")
async def add_custom(body: CustomIn, request: Request, admin: Admin, db: Db) -> dict:
    """A product the catalogue does not know, by its CPE (vendor:product from the NVD dictionary)."""
    cpe = body.cpe.removeprefix("cpe:2.3:")
    key = f"custom-{uuid.uuid4().hex[:12]}"
    vendor = cpe.split(":")[1].replace("_", " ")
    now = datetime.now(UTC)
    f = VendorFollow(product=key, enabled=True, custom={"label": body.label, "vendor": vendor[:1].upper() + vendor[1:], "cpe": cpe, "category": body.category}, created_at=now, updated_at=now)
    db.add(f)
    audit.record(db, admin, "catalog.custom_added", audit.target("product", key, body.label), {"cpe": cpe, "category": body.category})
    await db.commit()
    p = catalog.custom_product({**f.custom, "key": key})
    await advisory_cleanup.on_follow(db, p)  # its CPE may have been followed before: a full fetch
    await svc.relink(db, p)
    svc.bump([key])
    _wake(request)
    return {"key": key}


class VersionIn(_M):
    version: str = Field(min_length=1, max_length=200)  # a pasted line (SELECT @@VERSION); what is stored is at most 64
    label: str = Field(default="", max_length=100)
    count: int | None = Field(default=None, ge=1, le=100000)

    @field_validator("label")
    @classmethod
    def _label(cls, v: str) -> str:
        return plaintext.label(v)  # no direction or invisible characters (0.1.51)


def _no_twin(have: list[VendorVersion], norm: str, label: str, own: uuid.UUID | None = None) -> None:
    """The same version with the same label once per product (0.1.51 – before, a second "3.9.0" without a label was
    taken silently and showed as a twin). The same version with another label (a second site) stays fine."""
    key = label.casefold()
    if any(x.id != own and x.version == norm and (x.label or "").casefold() == key for x in have):
        raise api_error(409, "version_exists", version=norm, label=label)


def _checked(product: dict, text: str) -> str:
    c = version_input.check(product, text)
    if not c.ok:
        raise api_error(422, "version_invalid", reason=c.reason, example=version_input.example_for(product), **_check_extra(product, c))
    return c.value


def _entered(product: dict, text: str) -> dict:
    """What was typed, for the audit log, when it was looked up in a build table (vCenter's 8.0.3.00400 → 8.0 U3d)."""
    return {"entered": " ".join(text.split())} if svc.version_mapped(product, text) else {}


@router.post("/vendor/follows/{key}/versions")
async def add_version(key: str, body: VersionIn, request: Request, admin: Admin, db: Db) -> dict:
    f = await _follow(db, key)
    p = svc.product_of(f) or {}
    norm = _checked(p, body.version)
    have = (await svc.versions_of(db, [f.id])).get(f.id, [])
    if len(have) >= MAX_VERSIONS:
        raise api_error(422, "too_many_versions")
    _no_twin(have, norm, body.label)
    now = datetime.now(UTC)
    # entered: confirmed by the one who entered it (Versionen prüfen, app/catalog_care.py)
    v = VendorVersion(id=uuid.uuid4(), follow_id=f.id, version=norm, label=body.label, count=body.count, created_at=now, updated_at=now, confirmed_at=now, confirmed_by=admin.id)
    db.add(v)
    audit.record(db, admin, "catalog.version_added", _follow_target(f), {"version": norm, "label": body.label, "count": body.count} | _entered(p, body.version))
    await db.commit()
    svc.bump([key])
    _wake(request)  # evaluated right away (silently – the page shows it)
    return _version_out(v, p, await care.review_ctx(db, [v]))


async def _version(db, vid: uuid.UUID) -> tuple[VendorVersion, VendorFollow]:
    v = await db.get(VendorVersion, vid)
    if v is None:
        raise api_error(404, "not_found")
    return v, await db.get(VendorFollow, v.follow_id)


@router.put("/vendor/versions/{vid}")
async def update_version(vid: uuid.UUID, body: VersionIn, request: Request, admin: Admin, db: Db) -> dict:
    v, f = await _version(db, vid)
    p = svc.product_of(f) or {}
    norm = _checked(p, body.version)
    if f is not None:
        _no_twin((await svc.versions_of(db, [f.id])).get(f.id, []), norm, body.label, own=v.id)
    if norm != v.version:
        v.baseline_at = None  # another version: evaluated anew; what it finds then is the baseline
    if f is not None and (changes := audit.diff({"version": v.version, "label": v.label, "count": v.count}, {"version": norm, "label": body.label, "count": body.count}, ("version", "label", "count"))):
        audit.record(db, admin, "catalog.version_changed", _follow_target(f), {"changes": changes} | _entered(p, body.version))
    now = datetime.now(UTC)
    v.version, v.label, v.count, v.updated_at = norm, body.label, body.count, now
    v.confirmed_at, v.confirmed_by = now, admin.id  # changed (or saved as it is): confirmed
    await db.commit()
    svc.bump([f.product] if f else None)
    _wake(request)
    return _version_out(v, p, await care.review_ctx(db, [v]))


@router.delete("/vendor/versions/{vid}")
async def delete_version(vid: uuid.UUID, admin: Admin, db: Db) -> dict:
    v, f = await _version(db, vid)
    if f is not None:
        audit.record(db, admin, "catalog.version_deleted", _follow_target(f), {"version": v.version, "label": v.label})
    await db.delete(v)
    await db.commit()
    svc.bump([f.product] if f else None)
    return {"ok": True}


@router.get("/vendor/validate")
async def validate_version(user: Reader, product: Annotated[str, Query(max_length=80)], version: Annotated[str, Query(max_length=200)]) -> dict:
    p = catalog.product(product) or {"scheme": "generic"}
    c = version_input.check(p, version)
    # short: accepted, but less precise than the product's releases – the form asks for the whole version;
    # mapped: looked up or normalised (vCenter's 8.0.3.00400 → 8.0 U3d, "2019 CU15 Apr25HU" → 15.2.1748.24) – the form
    # shows "→ …" before it is saved; refused: the reason, the catalogue's hint, the product it belongs to, known lines
    return {
        "ok": c.ok,
        "normalized": c.value,
        "reason": c.reason or None,
        "short": c.ok and svc.short_version(p, c.value),
        "mapped": c.ok and c.mapped,
        "example": version_input.example_for(p),
    } | _check_extra(p, c)


@router.get("/vendor/cpe-search")
async def cpe_search(admin: Admin, db: Db, q: Annotated[str, Query(min_length=3, max_length=60)]) -> dict:
    """Vendor/product names of the NVD CPE dictionary (cached an hour; at most one request to NVD every 7 seconds)."""
    term = " ".join(q.split()).lower()
    hit = _cpe_cache.get(term)
    if hit and time.monotonic() - hit[0] < CPE_TTL:
        return {"items": hit[1], "cached": True}
    if time.monotonic() - _last_cpe_search[0] < 7.0:
        raise api_error(429, "rate_limited")
    _last_cpe_search[0] = time.monotonic()
    key = svc.nvd_key(await svc.config(db))
    from urllib.parse import urlencode

    try:
        body = await svc.get(f"{src.NVD_CPES}?{urlencode({'keywordSearch': term, 'resultsPerPage': 200})}", headers={"apiKey": key} if key else {}, has_key=bool(key), conditional=False, limit=8 * 1024 * 1024)
        items = await asyncio.to_thread(src.parse_cpes, body or b"{}")
    except NewsError as exc:
        return {"items": [], "error": exc.category}
    if len(_cpe_cache) > 200:
        _cpe_cache.clear()
    _cpe_cache[term] = (time.monotonic(), items)
    return {"items": items, "cached": False}


# ---------------------------------------------------------------- settings (admins)


STRUCTURED = svc.STRUCTURED  # the structured sources, each switched on its own


def _settings_out(cfg: dict) -> dict:
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "every_h": int(cfg.get("every_h") or 6),
        "eol_every_h": int(cfg.get("eol_every_h") or 24),
        "nvd_key_set": bool(cfg.get("nvd_key_enc")),
        **{k: bool(cfg.get(k, True)) for k in STRUCTURED},
        # the exploit lists (app/exploits.py), each on or off
        **{k: bool(cfg.get(k, d)) for k, d in exploits.SWITCHES.items()},
        # Versionen prüfen: a version not confirmed for longer than this is "bitte prüfen" (0: off)
        "review_days": care.review_days_of(cfg),
        # CSAF providers whose TLP:GREEN documents are allowed (default none – only TLP:CLEAR/WHITE)
        "csaf_green": sorted(_green(cfg)),
        "rev": int(cfg.get("rev") or 0),  # the saved state (409 stale when another admin saved in between)
    }


def _green(cfg: dict) -> frozenset[str]:
    from app import csaf_providers

    return csaf_providers.green_allowed(cfg)


class VendorSettingsIn(_M):
    enabled: bool = True
    every_h: int = Field(default=6, ge=1, le=48)
    eol_every_h: int = Field(default=24, ge=6, le=168)
    nvd_key: str = Field(default="", max_length=100, pattern=r"^[A-Za-z0-9-]*$")  # empty: keep
    clear_nvd_key: bool = False
    # the structured sources (None: as they are – a form that does not show them keeps them)
    csaf: bool | None = None
    cvelist: bool | None = None
    epss: bool | None = None
    osv: bool | None = None
    exploit_metasploit: bool | None = None
    exploit_exploitdb: bool | None = None
    exploit_nuclei: bool | None = None
    review_days: int | None = None  # None: as it is
    # the CSAF providers (csaf.yaml keys) whose TLP:GREEN documents are read (None: as it is)
    csaf_green: list[Annotated[str, Field(min_length=1, max_length=40)]] | None = Field(default=None, max_length=100)
    rev: int | None = None  # the state the form was loaded with

    @field_validator("csaf_green")
    @classmethod
    def _green_keys(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        from app import csaf_providers

        known = {p["key"] for p in csaf_providers.providers()}
        if bad := [k for k in v if k not in known]:
            raise ValueError(f"unknown CSAF provider: {', '.join(bad[:3])}")
        return sorted(set(v))

    @field_validator("review_days")
    @classmethod
    def _review(cls, v: int | None) -> int | None:
        if v is not None and v not in care.REVIEW_CHOICES:
            raise ValueError(f"one of {care.REVIEW_CHOICES}")
        return v


@router.get("/admin/vendor")
async def admin_vendor(admin: Admin, db: Db) -> dict:
    cfg = await svc.config(db)
    # without the per-CVE lookups (one row per CVE: story details, cvelistV5, OSV)
    states = list(await db.scalars(select(VendorFetch).where(_no_single()).order_by(VendorFetch.key)))
    cat = catalog.load()
    products = [p for f in await svc.follows(db) if (p := svc.product_of(f))]
    from app import csaf_providers

    needed = {x["key"] for x in csaf_providers.needed(products)}
    return {
        "structured": {
            "csaf_providers": [
                {"key": x["key"], "name": x["name"], "domain": x["domain"], "vendors": x["vendors"], "needed": x["key"] in needed, "green": x["key"] in _green(cfg)}
                for x in csaf_providers.providers()
            ],
            "osv_products": sum(1 for p in products if p.get("osv")),
            "exploit_sources": [{"key": x.key, "name": x.name, "url": x.url, "licence": x.licence, "default": x.default} for x in exploits.SOURCES.values()],
        },
        "settings": _settings_out(cfg),
        "catalog": {"catalog_version": catalog.catalog_version(), "generated_at": cat.get("generated_at"), "eol_generated_at": cat.get("eol_generated_at"), "products": len(cat["products"]), "counts": cat.get("counts")},
        "sources": [
            {"key": s.key, "last_ok_at": _iso(s.last_ok_at), "last_fetch_at": _iso(s.last_fetch_at), "next_fetch_at": _iso(s.next_fetch_at), "error": s.error, "items": s.items}
            for s in states
        ],
    }


@router.put("/admin/vendor")
async def put_vendor(body: VendorSettingsIn, request: Request, admin: Admin, db: Db) -> dict:
    cur = await svc.config(db)
    enc = "" if body.clear_nvd_key else encrypt_str(body.nvd_key) if body.nvd_key else cur.get("nvd_key_enc", "")
    switches = {k: bool(cur.get(k, True)) if getattr(body, k) is None else getattr(body, k) for k in STRUCTURED}
    switches |= {k: bool(cur.get(k, d)) if getattr(body, k) is None else getattr(body, k) for k, d in exploits.SWITCHES.items()}
    review_days = care.review_days_of(cur) if body.review_days is None else body.review_days
    was_green = _green(cur)
    green = sorted(was_green) if body.csaf_green is None else body.csaf_green
    value = {"enabled": body.enabled, "every_h": body.every_h, "eol_every_h": body.eol_every_h, "nvd_key_enc": enc, **switches, "review_days": review_days, "csaf_green": green}
    if changes := audit.diff({**cur, "csaf_green": sorted(was_green)}, value, value.keys()):
        audit.record(db, admin, "settings.changed", audit.target("settings", "vendor", "vendor"), {"changes": changes})
    out = await settings_store.put_rev(db, "vendor", value, body.rev)
    exploit_moved = any(bool(cur.get(k, d)) != switches[k] for k, d in exploits.SWITCHES.items())
    if any(bool(cur.get(k, True)) != switches[k] for k in STRUCTURED) or exploit_moved:
        svc.bump()  # a source switched off (or on again): its stored records leave (or join) the verdicts – svc.counts
    if exploit_moved:
        # the news' topic "poc" names the switched-on lists only (news.exploit_cves): every story's topics again, in the
        # background (news.backfill_topics, in chunks)
        from app import news

        await news.topics_again(db)
        await db.commit()
    if set(green) != was_green:
        from app import csaf_providers

        for key in set(green) - was_green:
            # allowed now: the provider's list is read again from the start (its GREEN documents were skipped before);
            # what is older than a week comes as the first fill does – shown, not notified
            st = await db.get(VendorFetch, f"csaf:{key}")
            if st is not None:
                st.cursor, st.next_fetch_at, st.etag, st.last_modified = None, None, None, None
        await db.commit()
        if was_green - set(green):
            await csaf_providers.purge_green(db, frozenset(green))  # no longer allowed: gone now (the round checks again)
    _wake(request)
    return _settings_out(out)


@router.post("/admin/vendor/fetch")
async def fetch_now(request: Request, admin: Admin, db: Db) -> dict:
    if not (await svc.config(db)).get("enabled", True):
        raise api_error(409, "vendor_off")
    f = getattr(request.app.state, "vendor_force", None)
    if f:
        f()
    return {"ok": True}


@router.post("/admin/vendor/catalog")
async def refresh_catalog(request: Request, admin: Admin, db: Db) -> dict:
    """Builds the catalogue anew from endoflife.date (in the background; at most every 10 minutes)."""
    if time.monotonic() - _last_catalog[0] < 600:
        raise api_error(429, "rate_limited")
    _last_catalog[0] = time.monotonic()
    audit.record(db, admin, "catalog.refreshed", audit.target("catalog", None, None), {"started": True})
    await db.commit()
    f = getattr(request.app.state, "vendor_catalog", None)
    if f:
        f()
    return {"ok": True}


# ---------------------------------------------------------------- Katalog-Pflege (catalogue self-test, admins)

_last_check = [-1e9]


@router.get("/admin/vendor/catalog-check")
async def catalog_check_overview(request: Request, admin: Admin, db: Db) -> dict:
    """The products whose catalogue entry needs care, with the reasons, and the state of the self-test."""
    loop = getattr(request.app.state, "catalog_check", None)
    return await catalog_check.overview(db, running=bool(loop and loop.running))


@router.post("/admin/vendor/catalog-check")
async def catalog_check_now(request: Request, admin: Admin, db: Db) -> dict:
    """"Jetzt prüfen": the followed products' CPEs at once (at most every 10 minutes), the local checks for all."""
    if not (await svc.config(db)).get("enabled", True):
        raise api_error(409, "vendor_off")
    if time.monotonic() - _last_check[0] < 600:
        raise api_error(429, "rate_limited")
    _last_check[0] = time.monotonic()
    loop = getattr(request.app.state, "catalog_check", None)
    if loop:
        loop.now()
    return {"ok": True}
