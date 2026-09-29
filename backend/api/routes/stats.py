from fastapi import Depends
from core.security import require_auth
from fastapi import APIRouter

from core.database import get_pool

router = APIRouter()


@router.get("/api/stats/summary")
async def stats_summary(user: str = Depends(require_auth)):
    """quick top-level numbers for the dashboard header cards"""
    pool = get_pool()
    async with pool.acquire() as conn:
        total_events = await conn.fetchval("SELECT COUNT(*) FROM attack_events")
        unique_ips = await conn.fetchval("SELECT COUNT(DISTINCT attacker_ip) FROM attack_events")
        total_creds = await conn.fetchval("SELECT COUNT(*) FROM captured_credentials")
        critical_threats = await conn.fetchval(
            "SELECT COUNT(*) FROM threat_scores WHERE score >= 75"
        )

    return {
        "total_events": total_events,
        "unique_attackers": unique_ips,
        "credentials_captured": total_creds,
        "critical_threats": critical_threats,
    }


@router.get("/api/stats/by-service")
async def stats_by_service(user: str = Depends(require_auth)):
    """attack counts broken down per honeypot service, for a pie/bar chart"""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT service, COUNT(*) as count
            FROM attack_events
            GROUP BY service
            ORDER BY count DESC
            """
        )
    return [dict(row) for row in rows]


@router.get("/api/stats/top-attackers")
async def top_attackers(limit: int = 10, user: str = Depends(require_auth)):
    """most active attacker IPs, for a leaderboard widget"""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT attacker_ip, country,  total_events, score, threat_level
            FROM threat_scores
            ORDER BY total_events DESC
            LIMIT $1
            """,
            limit,
        )
    return [dict(row) for row in rows]


@router.get("/api/stats/timeline")
async def stats_timeline(hours: int = 24, user: str = Depends(require_auth)):
    """events bucketed by hour, for a time-series chart"""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT date_trunc('hour', timestamp) as bucket, COUNT(*) as count
            FROM attack_events
            WHERE timestamp > NOW() - ($1 || ' hours')::interval
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            str(hours),
        )
    return [dict(row) for row in rows]
