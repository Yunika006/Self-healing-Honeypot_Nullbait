import asyncio
import logging
import os
import sys

import asyncpg
import docker

from healer import attempt_restart, record_recovery
from isolator import check_for_isolation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

log = logging.getLogger("nullbait.watchdog")

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "db")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "nullbait_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "nullbait_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "nullbait_secret_2024")

CHECK_INTERVAL_SECONDS = 10

# map our logical "service" names to actual docker container names
# this is what ties recovery's monitoring back to the same 'service'
# labels used everywhere else in the system (attack_events, etc.)
MONITORED_CONTAINERS = {
    "honeypot": "nullbait_honeypot",
    "backend": "nullbait_backend",
    "detection": "nullbait_detection",
    "frontend": "nullbait_frontend",
}

# cpu% above this for a sustained period gets flagged as "degraded"
# not necessarily compromised, but worth a closer look
CPU_DEGRADED_THRESHOLD = 80.0


async def connect_with_retry():
    attempts = 0
    while attempts < 10:
        try:
            pool = await asyncpg.create_pool(
                host=POSTGRES_HOST, port=POSTGRES_PORT, database=POSTGRES_DB,
                user=POSTGRES_USER, password=POSTGRES_PASSWORD,
                min_size=2, max_size=5,
            )
            log.info("watchdog connected to postgres")
            return pool
        except Exception as e:
            attempts += 1
            log.warning("db not ready (attempt %d/10): %s", attempts, e)
            await asyncio.sleep(3)
    raise RuntimeError("could not connect to postgres")


def get_docker_client():
    """connects to the docker daemon via the mounted socket"""
    return docker.from_env()


def get_container_stats(client, container_name: str) -> dict:
    """
    returns {"status": "healthy"|"degraded"|"down", "cpu_percent": float,
             "mem_mb": float, "uptime_secs": int, "note": str}
    """
    try:
        container = client.containers.get(container_name)
    except docker.errors.NotFound:
        return {
            "status": "down",
            "cpu_percent": None,
            "mem_mb": None,
            "uptime_secs": None,
            "note": "container not found — may have been removed",
        }

    if container.status != "running":
        return {
            "status": "down",
            "cpu_percent": None,
            "mem_mb": None,
            "uptime_secs": None,
            "note": f"container status: {container.status}",
        }

    # pull a single stats snapshot (stream=False = one-shot, not continuous)
    try:
        stats = container.stats(stream=False)
        cpu_percent = _calculate_cpu_percent(stats)
        mem_mb = stats["memory_stats"].get("usage", 0) / (1024 * 1024)

        # uptime from container's StartedAt timestamp
        started_at = container.attrs["State"]["StartedAt"]
        from datetime import datetime, timezone
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        uptime_secs = int((datetime.now(timezone.utc) - started).total_seconds())

        status = "degraded" if cpu_percent > CPU_DEGRADED_THRESHOLD else "healthy"
        note = "high cpu usage detected" if status == "degraded" else "running normally"

        return {
            "status": status,
            "cpu_percent": round(cpu_percent, 2),
            "mem_mb": round(mem_mb, 2),
            "uptime_secs": uptime_secs,
            "note": note,
        }
    except Exception as e:
        # container is running but stats call failed for some reason —
        # don't treat this as "down", just report what we know
        return {
            "status": "healthy",
            "cpu_percent": None,
            "mem_mb": None,
            "uptime_secs": None,
            "note": f"stats unavailable: {e}",
        }


def _calculate_cpu_percent(stats: dict) -> float:
    """
    docker's raw stats give cumulative cpu usage, not a percentage.
    this is the standard formula docker itself uses internally to
    convert that into a usable cpu% number.
    """
    try:
        cpu_delta = (
            stats["cpu_stats"]["cpu_usage"]["total_usage"]
            - stats["precpu_stats"]["cpu_usage"]["total_usage"]
        )
        system_delta = (
            stats["cpu_stats"]["system_cpu_usage"]
            - stats["precpu_stats"]["system_cpu_usage"]
        )
        num_cpus = stats["cpu_stats"].get("online_cpus", 1)

        if system_delta > 0 and cpu_delta > 0:
            return (cpu_delta / system_delta) * num_cpus * 100.0
        return 0.0
    except (KeyError, ZeroDivisionError):
        return 0.0


async def write_health_row(conn, service: str, stats: dict):
    await conn.execute(
        """
        INSERT INTO service_health (service, status, cpu_percent, mem_mb, uptime_secs, note)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        service, stats["status"], stats["cpu_percent"], stats["mem_mb"],
        stats["uptime_secs"], stats["note"],
    )


async def fire_alert(conn, severity: str, title: str, message: str, service: str = None):
    await conn.execute(
        """
        INSERT INTO alerts (severity, title, message, service)
        VALUES ($1, $2, $3, $4)
        """,
        severity, title, message, service,
    )


async def check_all_containers(pool, docker_client):
    async with pool.acquire() as conn:
        for service_name, container_name in MONITORED_CONTAINERS.items():
            stats = get_container_stats(docker_client, container_name)
            await write_health_row(conn, service_name, stats)

            if stats["status"] == "down":
                log.warning("%s is DOWN — attempting restart", service_name)

                success, duration_ms, notes = attempt_restart(docker_client, container_name)
                await record_recovery(conn, service_name, "restart", stats["note"], success, duration_ms, notes)

                if success:
                    await fire_alert(
                        conn, "warning",
                        f"{service_name} was restarted",
                        f"Container {container_name} had stopped and was automatically restarted. Reason: {stats['note']}",
                        service_name,
                    )
                    log.info("%s successfully restarted in %dms", service_name, duration_ms)
                else:
                    await fire_alert(
                        conn, "critical",
                        f"{service_name} restart FAILED",
                        f"Could not restart {container_name}. Manual intervention required. {notes}",
                        service_name,
                    )
                    log.error("%s restart failed: %s", service_name, notes)

            elif stats["status"] == "degraded":
                log.info("%s is degraded — cpu: %s%%", service_name, stats["cpu_percent"])
                await fire_alert(
                    conn, "warning",
                    f"{service_name} showing high resource usage",
                    f"CPU at {stats['cpu_percent']}% — monitor for potential compromise or abuse",
                    service_name,
                )

        # separate check: look for ips that should be isolated based on threat score
        await check_for_isolation(conn)


async def main():
    log.info("NullBait recovery watchdog starting")
    pool = await connect_with_retry()
    docker_client = get_docker_client()

    while True:
        try:
            await check_all_containers(pool, docker_client)
        except Exception as e:
            log.error("error during health check cycle: %s", e)

        await asyncio.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("watchdog shutting down")
