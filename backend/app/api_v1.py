"""The documented, read-only API for API tokens (scope `read`, app/api_tokens.py): the news, the followed products of
Vendor News with their versions and their findings. Stable shapes of their own (the response models below) – the web
UI's endpoints change with the UI and are never reachable with a token.

Nothing here knows a person: no read marks, no teams, no notes of the admins, no names of users. A token sees what every
signed-in reader sees on the shared pages ("Alle" in Vendor News).

The OpenAPI description (`openapi()`) is made from these routes and /metrics only and is served to admins
(GET /api/admin/api-tokens/openapi.json) – the app has no public /docs."""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Path, Query
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select
from sqlalchemy.dialects.postgresql import array as pg_array

from app import __version__, epss, exploits
from app import news as news_svc
from app import vendor as svc
from app.api_tokens import ReadToken
from app.config import get_config
from app.db import contains, fold
from app.deps import Db, api_error
from app.models import NewsItem, NewsSource

router = APIRouter(prefix="/api/v1")
Severity = Literal["critical", "high", "medium", "low", "info"]
Topic = Literal["zeroday", "exploited", "ransomware", "nopatch", "breach", "supply", "phishing", "ot"]
TOPIC_TEXT = (
    "Topics of a story, detected by rules in its title and teaser and from structured data (CISA KEV, the advisory): "
    "`zeroday`, `exploited` (actively exploited), `ransomware`, `nopatch` (no patch available), `breach` (incident or "
    "data leak), `supply` (supply chain), `phishing` (phishing and social engineering), `ot` (OT/ICS)"
)
Status = Literal["affected", "possible", "service", "unversioned", "stale", "not_affected"]
TOKEN_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"description": "No token, or an unknown, malformed, revoked or expired one (always the same answer)"},
    403: {"description": "The token lacks the scope, or the request is not a GET of /api/v1/… or /metrics"},
    429: {"description": "Too many requests of this token, or too many wrong tokens from this address (Retry-After)"},
}


# ---------------------------------------------------------------- shapes


class SourceRef(BaseModel):
    key: str = Field(description="Stable key of the source (e.g. `cisa-kev`)")
    name: str


class Story(BaseModel):
    id: uuid.UUID
    title: str
    summary: str = ""
    url: str
    source: SourceRef
    published_at: datetime
    severity: Severity
    cves: list[str] = Field(description="CVE ids named in the story (at most 30)")
    also_in: list[str] = Field(default_factory=list, description="Further sources that carry the same story")
    topics: list[Topic] = Field(default_factory=list, description=TOPIC_TEXT)


class StoryPage(BaseModel):
    items: list[Story]
    next: str | None = Field(description="Pass as `before` for the next (older) page; null: no more")


class EpssScore(BaseModel):
    cve: str
    score: float = Field(description="FIRST EPSS: probability of exploitation in the next 30 days (0–1)")
    percentile: float
    date: str | None = None


class ExploitHint(BaseModel):
    cve: str
    source: Literal["metasploit", "exploitdb", "nuclei"] = Field(description="The list naming public exploit code (or a ready-made exploit check) for the CVE")
    url: str = Field(description="The entry in that list")
    first_seen: str | None = Field(default=None, description="When Cobe News first saw it there")


class StoryDetail(Story):
    epss: list[EpssScore] = Field(default_factory=list, description="EPSS of the story's CVEs, likeliest first")
    exploits: list[ExploitHint] = Field(default_factory=list, description="Public exploits for the story's CVEs (switched-on exploit lists)")


class Version(BaseModel):
    id: uuid.UUID
    version: str
    label: str | None = None
    valid: bool = Field(description="Whether the version fits the product's version scheme")


class Product(BaseModel):
    key: str
    label: str
    vendor: str = ""
    category: str = ""
    cloud: bool = False


class FindingVersion(BaseModel):
    version: str | None
    status: Status
    fixed: str | None = None


class Kev(BaseModel):
    added: str | None = None
    due: str | None = None
    ransomware: bool | str | None = None


class Finding(BaseModel):
    id: str = Field(description="Stable id of the advisory (`<source>:<ident>`)")
    source: str
    ident: str
    title: str | None = None
    headline: str | None = None
    url: str | None = None
    cves: list[str] = []
    cvss: float | None = None
    severity: Severity | str
    exploited: bool = Field(description="Known to be exploited (CISA KEV or the vendor)")
    kev: Kev | None = None
    epss: EpssScore | None = None
    exploits: list[ExploitHint] = Field(default_factory=list, description="Public exploits for the finding's CVEs (switched-on exploit lists)")
    status: Status = Field(description="The worst verdict over the versions entered")
    published_at: str | None = None
    versions: list[FindingVersion] = []


class ProductFinding(Finding):
    product: str = Field(description="Key of the followed product")


class Counts(BaseModel):
    affected: int = 0
    possible: int = 0
    service: int = 0
    unversioned: int = 0
    stale: int = 0
    critical: int = 0
    exploited: int = 0
    critical_affected: int = 0
    exploited_affected: int = 0


class ProductSummary(Product):
    tags: list[str] = []
    versions: list[Version]
    counts: Counts
    urgency: str = Field(description="exploited | critical | affected | possible | info | ok")


class ProductList(BaseModel):
    items: list[ProductSummary]


class ProductDetail(Product):
    tags: list[str] = []
    versions: list[Version]
    findings: list[Finding]
    offset: int
    limit: int
    shown: int = Field(description="Findings matching the filter in all (the page is `offset`…`offset+limit`)")
    by_status: dict[str, int]


class FindingPage(BaseModel):
    items: list[ProductFinding]
    total: int
    offset: int
    limit: int


# ---------------------------------------------------------------- news


def _story(i: NewsItem, s: NewsSource, *, cves: int = 30) -> dict:
    return {
        "id": i.id,
        "title": i.title,
        "summary": i.summary or "",
        "url": i.url,
        "source": {"key": s.key, "name": s.name},
        "published_at": i.published_at,
        "severity": i.severity,
        "cves": list(i.cves or [])[:cves],
        "also_in": list(i.also_in or []),
        "topics": [t for t in news_svc.TOPICS if t in (i.topics or [])],
    }


def _cursor(value: str) -> tuple[datetime, uuid.UUID]:
    try:
        at, sid = value.split("|", 1)
        d = datetime.fromisoformat(at)
        d = (d if d.tzinfo else d.replace(tzinfo=UTC)).astimezone(UTC)
        return d, uuid.UUID(sid)
    except (ValueError, OverflowError) as exc:
        raise api_error(422, "invalid_cursor") from exc


@router.get("/news", response_model=StoryPage, responses=TOKEN_ERRORS, summary="Stories, newest first", operation_id="listNews", tags=["News"])
async def list_news(
    token: ReadToken,
    db: Db,
    severity: Annotated[list[Severity], Query(description="Only these severities (repeat the parameter)")] = [],  # noqa: B006
    source: Annotated[list[str], Query(max_length=50, description="Only these sources, by key (repeat the parameter)")] = [],  # noqa: B006
    topic: Annotated[list[Topic], Query(max_length=8, description="Only stories with one of these topics (repeat the parameter; OR within the topics)")] = [],  # noqa: B006
    q: Annotated[str, Query(max_length=100, description="Words in title, summary or CVE ids (case and accents ignored)")] = "",
    since: Annotated[datetime | None, Query(description="Only stories published at or after this time (ISO 8601)")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before: Annotated[str | None, Query(max_length=100, description="`next` of the previous page")] = None,
) -> dict:
    """The stories of the switched-on sources, newest first, paged by a cursor (no offset: stories arriving meanwhile
    neither repeat nor skip one)."""
    ids: list[uuid.UUID] = []
    if source:
        ids = list(await db.scalars(select(NewsSource.id).where(NewsSource.key.in_(source[:50]))))
        if not ids:
            return {"items": [], "next": None}
    where = [news_svc.visible(ids)]
    if severity:
        where.append(NewsItem.severity.in_(severity))
    if topic:
        where.append(NewsItem.topics.op("?|")(pg_array(sorted(set(topic)))))
    if q.strip():
        where.append(NewsItem.search.like(contains(q.strip()[:100])))
    if since is not None:
        where.append(NewsItem.published_at >= (since if since.tzinfo else since.replace(tzinfo=UTC)))
    if before:
        at, sid = _cursor(before)
        where.append(or_(NewsItem.published_at < at, and_(NewsItem.published_at == at, NewsItem.id < sid)))
    stmt = select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(*where)
    rows = (await db.execute(stmt.order_by(NewsItem.published_at.desc(), NewsItem.id.desc()).limit(limit + 1))).all()
    out = {"items": [_story(i, s) for i, s in rows[:limit]], "next": None}
    if len(rows) > limit:
        last = rows[limit - 1][0]
        out["next"] = f"{last.published_at.isoformat()}|{last.id}"
    return out


@router.get("/news/sources", response_model=list[SourceRef], responses=TOKEN_ERRORS, summary="The switched-on news sources", operation_id="listNewsSources", tags=["News"])
async def news_sources(token: ReadToken, db: Db) -> list[dict]:
    rows = sorted(await db.scalars(select(NewsSource).where(NewsSource.enabled.is_(True))), key=lambda s: (fold(s.name), s.key))
    return [{"key": s.key, "name": s.name} for s in rows]


@router.get("/news/{story_id}", response_model=StoryDetail, responses={**TOKEN_ERRORS, 404: {"description": "No such story"}}, summary="One story", operation_id="getNews", tags=["News"])
async def get_story(story_id: uuid.UUID, token: ReadToken, db: Db) -> dict:
    row = (await db.execute(select(NewsItem, NewsSource).join(NewsSource, NewsSource.id == NewsItem.source_id).where(NewsItem.id == story_id, news_svc.visible()))).first()
    if row is None:
        raise api_error(404, "not_found")
    i, s = row
    out = _story(i, s)
    scores = await epss.scores(db, [c.upper() for c in (i.cves or [])[:60]])
    out["epss"] = sorted(scores.values(), key=lambda e: -e["score"])[:12]
    named = [c.upper() for c in (i.cves or [])[:60]]
    out["exploits"] = exploits.brief(await exploits.of_cves(db, named), named, 12)
    return out


# ---------------------------------------------------------------- Vendor News


def _product(p: dict) -> dict:
    scheme = p.get("scheme") or "generic"
    return {"key": p["key"], "label": p.get("label") or p["key"], "vendor": p.get("vendor") or "", "category": p.get("category") or "other", "cloud": bool(p.get("cloud")) or scheme == "cloud"}


def _version(v, p: dict) -> dict:  # noqa: ANN001
    ok, _, _ = svc.validate_version(p, v.version)
    return {"id": v.id, "version": v.version, "label": v.label, "valid": ok}


def _finding(x: dict) -> dict:
    return {
        **{k: x.get(k) for k in ("id", "source", "ident", "title", "headline", "url", "cvss", "severity", "kev", "epss", "status", "published_at")},
        "cves": list(x.get("cves") or []),
        "exploited": bool(x.get("exploited")),
        "exploits": list(x.get("exploit") or []),
        "versions": [{"version": r.get("version"), "status": r.get("status"), "fixed": r.get("fixed")} for r in x.get("versions") or []],
    }


async def _views(db) -> list[tuple]:  # noqa: ANN001
    """(follow, versions, view) of every switched-on followed product – the cached views of the overview."""
    fs = await svc.follows(db)
    if not fs:
        return []
    vers = await svc.versions_of(db, [f.id for f in fs])
    kev, euvd = await svc.kev_index(db), await svc.euvd_cves(db)
    return [(f, vers.get(f.id, []), await svc.product_view(db, f, vers.get(f.id, []), kev=kev, euvd=euvd)) for f in fs]


def _counts(fs: list[dict]) -> dict:
    top = [f for f in fs if f["status"] in ("affected", "possible", "service", "unversioned")]
    hit = [f for f in fs if f["status"] == "affected"]
    return {
        "affected": len(hit),
        "possible": sum(1 for x in fs if x["status"] == "possible"),
        "service": sum(1 for x in fs if x["status"] == "service"),
        "unversioned": sum(1 for x in fs if x["status"] == "unversioned"),
        "stale": sum(1 for x in fs if x["status"] == "stale"),
        "critical": sum(1 for x in top if x["severity"] == "critical"),
        "exploited": sum(1 for x in top if x["exploited"]),
        "critical_affected": sum(1 for x in hit if x["severity"] == "critical"),
        "exploited_affected": sum(1 for x in hit if x["exploited"]),
    }


@router.get("/vendor/products", response_model=ProductList, responses=TOKEN_ERRORS, summary="The followed products", operation_id="listProducts", tags=["Vendor News"])
async def products(token: ReadToken, db: Db) -> dict:
    """Every followed product with its versions, how many findings of each kind concern it and how urgent it is."""
    items = []
    for f, vs, view in await _views(db):
        p = view["product"]
        counts = _counts(view["findings"])
        releases = [svc.release_info(p, v.version) or {} for v in vs]
        items.append({**_product(p), "tags": list(f.tags or []), "versions": [_version(v, p) for v in vs], "counts": counts, "urgency": svc.urgency(counts, releases)})
    return {"items": items}


@router.get(
    "/vendor/products/{key}",
    response_model=ProductDetail,
    responses={**TOKEN_ERRORS, 404: {"description": "Not a followed product"}},
    summary="One followed product with its findings",
    operation_id="getProduct",
    tags=["Vendor News"],
)
async def product(
    key: Annotated[str, Path(max_length=200, description="Key of the followed product")],
    token: ReadToken,
    db: Db,
    status: Annotated[list[Status], Query(description="Only findings with these verdicts (default: all but not_affected)")] = [],  # noqa: B006
    offset: Annotated[int, Query(ge=0, le=100000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict:
    """The findings in the order of the app: affected, possibly affected, …, most relevant first."""
    hit = next(((f, vs, view) for f, vs, view in await _views(db) if f.product == key), None)
    if hit is None:
        raise api_error(404, "not_found")
    f, vs, view = hit
    p = view["product"]
    fs = view["findings"]
    want = set(status) or {s for s in Status.__args__ if s != "not_affected"}  # type: ignore[attr-defined]
    shown = [x for x in fs if x["status"] in want]
    by_status: dict[str, int] = {}
    for x in fs:
        by_status[x["status"]] = by_status.get(x["status"], 0) + 1
    return {
        **_product(p),
        "tags": list(f.tags or []),
        "versions": [_version(v, p) for v in vs],
        "findings": [_finding(x) for x in shown[offset : offset + limit]],
        "offset": offset,
        "limit": limit,
        "shown": len(shown),
        "by_status": by_status,
    }


@router.get("/vendor/findings", response_model=FindingPage, responses=TOKEN_ERRORS, summary="Findings across all followed products", operation_id="listFindings", tags=["Vendor News"])
async def findings(
    token: ReadToken,
    db: Db,
    status: Annotated[list[Status], Query(description="Verdicts (default: affected and possible)")] = [],  # noqa: B006
    severity: Annotated[list[Severity], Query(description="Only these severities")] = [],  # noqa: B006
    exploited: Annotated[bool | None, Query(description="true: only known exploited ones")] = None,
    offset: Annotated[int, Query(ge=0, le=100000)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict:
    """One list for a SIEM or a ticket system: each finding once per product, the most relevant first."""
    want = set(status) or {"affected", "possible"}
    rows: list[dict] = []
    for f, _vs, view in await _views(db):
        for x in view["findings"]:
            if x["status"] not in want or (severity and x["severity"] not in severity) or (exploited is not None and bool(x["exploited"]) != exploited):
                continue
            rows.append({**_finding(x), "product": f.product})
    order = {"affected": 0, "possible": 1, "service": 2, "unversioned": 3, "stale": 4, "not_affected": 5}
    rows.sort(key=lambda r: (order.get(r["status"], 9), not r["exploited"], -(r["cvss"] or 0), r["product"], r["id"]))
    return {"items": rows[offset : offset + limit], "total": len(rows), "offset": offset, "limit": limit}


# ---------------------------------------------------------------- the description


def openapi() -> dict:
    """OpenAPI 3.1 of /api/v1 and /metrics – made from the routes themselves, so it never drifts from them."""
    from app import metrics

    spec = get_openapi(
        title="Cobe News API",
        version=__version__,
        description=(
            "Read-only access with an API token (Settings → API & metrics). Send it as `Authorization: Bearer cnt_…`. "
            "Scope `read`: everything under /api/v1. Scope `metrics`: /metrics (Prometheus text format). Only GET; "
            "never together with a session cookie."
        ),
        routes=[*router.routes, *metrics.router.routes],
        servers=[{"url": get_config().base_url}],
    )
    spec.setdefault("components", {})["securitySchemes"] = {"bearer": {"type": "http", "scheme": "bearer", "description": "An API token (cnt_…)"}}
    spec["security"] = [{"bearer": []}]
    for path, ops in spec.get("paths", {}).items():
        for op in ops.values():
            op["x-scope"] = "metrics" if path == "/metrics" else "read"
    return spec
