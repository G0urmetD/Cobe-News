"""Admin only: Quellen-Gesundheit (app/source_health.py) – every source with its state, and one source's history."""

from typing import Literal

from fastapi import APIRouter, Path

from app import source_health
from app.deps import Admin, Db, api_error

router = APIRouter(prefix="/api/admin/source-health", tags=["admin"])


@router.get("")
async def overview(admin: Admin, db: Db) -> dict:
    """{at, counts: {healthy, slow, disturbed, dead, off, never}, items: [one per news source, Vendor News family and structured
    source (CSAF providers, cvelistV5, EPSS, OSV)]}."""
    return await source_health.overview(db)


@router.get("/{kind}/{key:path}")
async def detail(admin: Admin, db: Db, kind: Literal["news", "vendor", "structured"], key: str = Path(min_length=1, max_length=300)) -> dict:
    """One source (a Vendor News family with its queries): recent fetches, errors, state changes."""
    out = await source_health.detail(db, kind, key)
    if out is None:
        raise api_error(404, "not_found")
    return out
