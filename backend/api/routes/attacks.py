from fastapi import Depends
from core.security import require_auth
from fastapi import APIRouter, Query

from core.database import get_pool

router = APIRouter()


@router.get("/api/attacks")
async def list_attacks(
    limit: int = Query(50, le=500),
    service: str | None = None,
    attacker_ip: str | None = None,
    user: str = Depends(require_auth),
):
    """
    returns recent attack events, newest first.
    optionally filter by service ('ssh','http','ftp','api') or a specific ip.
    """
    pool = get_pool()

    conditions = []
    params = []
    idx = 1

    if service:
        conditions.append(f"service = ${idx}")
        params.append(service)
        idx += 1

    if attacker_ip:
        conditions.append(f"attacker_ip = ${idx}")
        params.append(attacker_ip)
        idx += 1

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)

    query = f"""
        SELECT id, timestamp, attacker_ip, country, city, service,
               event_type, username, password, command, threat_score, threat_level
        FROM attack_events
        {where_clause}
        ORDER BY timestamp DESC
        LIMIT ${idx}
    """

    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *params)

    return [dict(row) for row in rows]


@router.get("/api/attacks/{attack_id}")
async def get_attack(attack_id: str, user: str = Depends(require_auth)):
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM attack_events WHERE id = $1", attack_id
        )
    if not row:
        return {"error": "not found"}
    return dict(row)
