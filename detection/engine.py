import asyncio
import logging
import os
import sys

import asyncpg

from rules import brute_force, sqli, cmdi, portscan
from scorer import combine_scores

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)

log = logging.getLogger("nullbait.detection")

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "db")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB = os.getenv("POSTGRES_DB", "nullbait_db")
POSTGRES_USER = os.getenv("POSTGRES_USER", "nullbait_user")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "nullbait_secret_2024")

ANALYSIS_INTERVAL_SECONDS = 5      # how often we re-scan
LOOKBACK_WINDOW_SECONDS = int(os.getenv("BRUTE_FORCE_WINDOW", 30))
CRITICAL_THREAT_SCORE = int(os.getenv("CRITICAL_THREAT_SCORE", 75))

RULES = [brute_force, sqli, cmdi, portscan]


async def connect_with_retry():
    attempts = 0
    while attempts < 10:
        try:
            pool = await asyncpg.create_pool(
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                database=POSTGRES_DB,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD,
                min_size=2,
                max_size=5,
            )
            log.info("detection engine connected to postgres")
            return pool
        except Exception as e:
            attempts += 1
            log.warning("db not ready (attempt %d/10): %s", attempts, e)
            await asyncio.sleep(3)
    raise RuntimeError("could not connect to postgres")


async def get_recent_ips(conn) -> list[str]:
    """which attacker ips have been active in our lookback window"""
    rows = await conn.fetch(
        f"""
        SELECT DISTINCT attacker_ip
        FROM attack_events
        WHERE timestamp > NOW() - INTERVAL '{LOOKBACK_WINDOW_SECONDS} seconds'
        """
    )
    return [r["attacker_ip"] for r in rows]


async def get_events_for_ip(conn, ip: str) -> list[dict]:
    rows = await conn.fetch(
        f"""
        SELECT service, event_type, raw_payload, username, password, command
        FROM attack_events
        WHERE attacker_ip = $1
          AND timestamp > NOW() - INTERVAL '{LOOKBACK_WINDOW_SECONDS} seconds'
        """,
        ip,
    )
    return [dict(r) for r in rows]


async def analyze_ip(conn, ip: str):
    events = await get_events_for_ip(conn, ip)
    if not events:
        return

    rule_results = [rule.check(events) for rule in RULES]
    result = combine_scores(rule_results)

    # figure out which specific attack-type flags to set on threat_scores
    detected_types = {
        "brute_force": rule_results[0]["detected"],
        "sql_injection": rule_results[1]["detected"],
        "cmd_injection": rule_results[2]["detected"],
        "port_scan": rule_results[3]["detected"],
    }

    await conn.execute(
        """
        UPDATE threat_scores
        SET score = $2,
            threat_level = $3,
            brute_force = brute_force OR $4,
            sql_injection = sql_injection OR $5,
            cmd_injection = cmd_injection OR $6,
            port_scan = port_scan OR $7,
            last_seen = NOW()
        WHERE attacker_ip = $1
        """,
        ip, result["score"], result["level"],
        detected_types["brute_force"], detected_types["sql_injection"],
        detected_types["cmd_injection"], detected_types["port_scan"],
    )

    # also stamp the most recent events from this ip with the current score
    # so the dashboard's attack feed shows live threat levels too
    await conn.execute(
        f"""
        UPDATE attack_events
        SET threat_score = $2, threat_level = $3,
            flagged = $4, flag_reason = $5
        WHERE attacker_ip = $1
          AND timestamp > NOW() - INTERVAL '{LOOKBACK_WINDOW_SECONDS} seconds'
        """,
        ip, result["score"], result["level"],
        result["score"] >= 25,
        "; ".join(result["reasons"]) if result["reasons"] else None,
    )

    if result["reasons"]:
        log.info("ip %s scored %d (%s) — %s", ip, result["score"], result["level"], result["reasons"])

    # fire an alert if this crosses the critical threshold
    if result["score"] >= CRITICAL_THREAT_SCORE:
        # avoid spamming duplicate alerts — check if we already alerted
        # for this ip in the last lookback window
        existing = await conn.fetchval(
            f"""
            SELECT COUNT(*) FROM alerts
            WHERE attacker_ip = $1
              AND timestamp > NOW() - INTERVAL '{LOOKBACK_WINDOW_SECONDS} seconds'
            """,
            ip,
        )
        if existing == 0:
            await conn.execute(
                """
                INSERT INTO alerts (severity, title, message, attacker_ip)
                VALUES ($1, $2, $3, $4)
                """,
                "critical",
                f"Critical threat detected from {ip}",
                "; ".join(result["reasons"]),
                ip,
            )
            log.warning("CRITICAL ALERT fired for %s — score %d", ip, result["score"])


async def analysis_loop(pool):
    while True:
        try:
            async with pool.acquire() as conn:
                ips = await get_recent_ips(conn)
                for ip in ips:
                    await analyze_ip(conn, ip)
        except Exception as e:
            log.error("error during analysis cycle: %s", e)

        await asyncio.sleep(ANALYSIS_INTERVAL_SECONDS)


async def main():
    log.info("NullBait detection engine starting")
    pool = await connect_with_retry()
    await analysis_loop(pool)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("detection engine shutting down")
