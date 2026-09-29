import logging

from core.metrics import attack_events_total, login_attempts_total
from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel

from core.database import get_pool
from services.event_bus import event_bus

log = logging.getLogger("nullbait.internal")

router = APIRouter()


class IncomingEvent(BaseModel):
    """
    matches whatever the honeypot's log_event() sends.
    everything optional except the core identifying fields,
    since not every event type has every field
    (e.g. a port scan has no username/password).
    """
    timestamp: datetime
    attacker_ip: str
    attacker_port: int | None = None
    service: str
    honeypot_port: int | None = None
    event_type: str
    raw_payload: str | None = None
    username: str | None = None
    password: str | None = None
    command: str | None = None
    country: str | None = None
    city: str | None = None
    isp: str | None = None
    user_agent: str | None = None
    path: str | None = None
    method: str | None = None
    auth_header: str | None = None
    body_preview: str | None = None
    attack_type: str | None = None


@router.post("/internal/events")
async def receive_event(event: IncomingEvent):
    """
    the honeypot posts here for literally every interaction —
    connects, login attempts, commands, path probes, everything.
    we store the raw event, then nudge the session + credential
    tables, then push it out to any connected dashboard.
    """
    pool = get_pool()

    async with pool.acquire() as conn:
        # 1. insert into attack_events — the master log
        row = await conn.fetchrow(
            """
            INSERT INTO attack_events
                (timestamp, attacker_ip, attacker_port, country, city, isp,
                 service, honeypot_port, event_type, raw_payload,
                 username, password, command)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id, threat_score, threat_level
            """,
            event.timestamp, event.attacker_ip, event.attacker_port,
            event.country, event.city, event.isp,
            event.service, event.honeypot_port, event.event_type,
            event.raw_payload, event.username, event.password, event.command,
        )

        # 2. upsert the session — create if new, bump counters if existing
        await conn.execute(
            """
            INSERT INTO attacker_sessions
                (attacker_ip, service, started_at, last_seen_at,
                 total_events, login_attempts, commands_run, country, city, user_agent)
            VALUES ($1, $2, NOW(), NOW(), 1, $3, $4, $5, $6, $7)
            ON CONFLICT DO NOTHING
            """,
            event.attacker_ip, event.service,
            1 if event.event_type == "login_attempt" else 0,
            1 if event.event_type == "command" else 0,
            event.country, event.city, event.user_agent,
        )

        # bump existing session stats (there's no unique constraint to
        # ON CONFLICT against above by design — sessions are append-friendly,
        # so we update the most recent active one for this ip+service instead)
        await conn.execute(
            """
            UPDATE attacker_sessions
            SET last_seen_at = NOW(),
                total_events = total_events + 1,
                login_attempts = login_attempts + $3,
                commands_run = commands_run + $4
            WHERE attacker_ip = $1 AND service = $2 AND is_active = TRUE
            """,
            event.attacker_ip, event.service,
            1 if event.event_type == "login_attempt" else 0,
            1 if event.event_type == "command" else 0,
        )

        # 3. if this was a credential attempt, log it to captured_credentials too
        if event.event_type == "login_attempt" and event.username:
            await conn.execute(
                """
                INSERT INTO captured_credentials (attacker_ip, service, username, password)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (service, username, password)
                DO UPDATE SET attempt_count = captured_credentials.attempt_count + 1
                """,
                event.attacker_ip, event.service, event.username, event.password or "",
            )

        # 4. ensure a threat_scores row exists for this ip (detection engine
        # in phase 4 will actually calculate real scores — for now just track presence)
        await conn.execute(
            """
            INSERT INTO threat_scores (attacker_ip, first_seen, last_seen, total_events, country)
            VALUES ($1, NOW(), NOW(), 1, $2)
            ON CONFLICT (attacker_ip)
            DO UPDATE SET
                last_seen = NOW(),
                total_events = threat_scores.total_events + 1
            """,
            event.attacker_ip, event.country,
        )

    # 5. push it out live to any dashboard currently connected via websocket
    attack_events_total.labels(service=event.service, event_type=event.event_type).inc()
    if event.event_type == "login_attempt":
        login_attempts_total.labels(service=event.service).inc()
    await event_bus.publish({
        "type": "attack_event",
        "id": str(row["id"]),
        "timestamp": event.timestamp,
        "attacker_ip": event.attacker_ip,
        "service": event.service,
        "event_type": event.event_type,
        "username": event.username,
        "password": event.password,
        "command": event.command,
        "country": event.country,
        "city": event.city,
        "threat_score": row["threat_score"],
    })

    log.info("stored event: %s from %s on %s", event.event_type, event.attacker_ip, event.service)

    return {"status": "received", "id": str(row["id"])}
