from fastapi import APIRouter, Depends

from core.database import get_pool
from core.security import require_auth

router = APIRouter()


@router.get("/api/services")
async def list_services(user: str = Depends(require_auth)):
    """latest health row per service, for the status indicator widgets"""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT DISTINCT ON (service) service, status, cpu_percent,
                   mem_mb, uptime_secs, timestamp, note
            FROM service_health
            ORDER BY service, timestamp DESC
            """
        )
    return [dict(row) for row in rows]


@router.get("/api/sessions")
async def list_sessions(active_only: bool = True, user: str = Depends(require_auth)):
    pool = get_pool()
    query = "SELECT * FROM attacker_sessions"
    if active_only:
        query += " WHERE is_active = TRUE"
    query += " ORDER BY last_seen_at DESC LIMIT 100"

    async with pool.acquire() as conn:
        rows = await conn.fetch(query)
    return [dict(row) for row in rows]


@router.get("/api/alerts")
async def list_alerts(acknowledged: bool | None = None, limit: int = 50, user: str = Depends(require_auth)):
    pool = get_pool()
    query = "SELECT * FROM alerts"
    params = []
    if acknowledged is not None:
        query += " WHERE acknowledged = $1"
        params.append(acknowledged)
    query += f" ORDER BY timestamp DESC LIMIT {limit}"

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
    return [dict(row) for row in rows]
