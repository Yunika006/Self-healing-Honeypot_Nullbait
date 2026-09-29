from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from core.config import settings
from core.metrics import unique_attackers_gauge, critical_threats_gauge
import logging
import sys
import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from core.database import connect_db, disconnect_db
from api.routes import internal, attacks, stats, services, auth
from api import websocket

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

log = logging.getLogger("nullbait.backend")

async def update_gauges_loop():
    """every 15s, recompute slower-moving gauge metrics from the database"""
    from core.database import get_pool
    while True:
        try:
            pool = get_pool()
            async with pool.acquire() as conn:
                unique_ips = await conn.fetchval("SELECT COUNT(DISTINCT attacker_ip) FROM attack_events")
                critical = await conn.fetchval("SELECT COUNT(*) FROM threat_scores WHERE score >= 75")
                unique_attackers_gauge.set(unique_ips or 0)
                critical_threats_gauge.set(critical or 0)
        except Exception as e:
            log.warning("gauge update failed: %s", e)
        await asyncio.sleep(15)

app = FastAPI(title="NullBait Backend", version="1.0.0")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# dashboard runs on a different port (3000) so we need CORS open
# for local dev. tighten this in phase 8 (security hardening).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    log.info("backend starting up")
    await connect_db()
    asyncio.create_task(update_gauges_loop())

@app.on_event("shutdown")
async def on_shutdown():
    log.info("backend shutting down")
    await disconnect_db()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "nullbait_backend"}


# mount all the route groups
app.include_router(internal.router)
app.include_router(attacks.router)
app.include_router(stats.router)
app.include_router(services.router)
app.include_router(websocket.router)
app.include_router(auth.router)

# prometheus metrics endpoint, for phase 7
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
