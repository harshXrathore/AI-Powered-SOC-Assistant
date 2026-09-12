"""
Health check endpoints.

Purpose:
    Lets Docker, load balancers, and uptime monitors verify the API and its
    critical dependencies (database, cache) are actually reachable — not
    just that the process is running.

API endpoints:
    GET /api/v1/health        -> liveness (process is up)
    GET /api/v1/health/ready  -> readiness (DB + Redis reachable)
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", status_code=status.HTTP_200_OK)
async def liveness() -> dict:
    return {"status": "ok"}


@router.get("/ready", status_code=status.HTTP_200_OK)
async def readiness(db: AsyncSession = Depends(get_db)) -> dict:
    checks = {"database": "unknown"}
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001 — surfaced to caller intentionally
        checks["database"] = f"error: {exc}"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks}
