import logging

import asyncpg

from core.config import settings

log = logging.getLogger("nullbait.database")

# global pool, created once on app startup, reused everywhere
_pool: asyncpg.Pool | None = None


async def connect_db():
    global _pool
    log.info("connecting to postgres at %s:%s", settings.POSTGRES_HOST, settings.POSTGRES_PORT)

    # retry loop — db container might still be warming up when backend starts
    import asyncio
    attempts = 0
    while attempts < 10:
        try:
            _pool = await asyncpg.create_pool(
                dsn=settings.database_url,
                min_size=2,
                max_size=10,
            )
            log.info("postgres connection pool ready")
            return
        except Exception as e:
            attempts += 1
            log.warning("db not ready yet (attempt %d/10): %s", attempts, e)
            await asyncio.sleep(3)

    raise RuntimeError("could not connect to postgres after 10 attempts")


async def disconnect_db():
    global _pool
    if _pool:
        await _pool.close()
        log.info("postgres pool closed")


def get_pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("database pool not initialized — did startup run?")
    return _pool
