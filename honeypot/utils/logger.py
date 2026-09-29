import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx

log = logging.getLogger("nullbait.event_logger")
BACKEND_URL = os.getenv("BACKEND_INTERNAL_URL", "http://backend:8000")
_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            base_url=BACKEND_URL,
            timeout=httpx.Timeout(5.0),
        )
    return _client


async def log_event(
    attacker_ip: str,
    attacker_port: int,
    service: str,
    honeypot_port: int,
    event_type: str,
    raw_payload: str = None,
    username: str = None,
    password: str = None,
    command: str = None,
    extra: dict = None,
) -> bool:
    """
    ship one event to the backend.
    returns True on success, False if backend is unreachable.
    non-blocking — we don't want a slow backend to stall the honeypot.
    """
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attacker_ip": attacker_ip,
        "attacker_port": attacker_port,
        "service": service,
        "honeypot_port": honeypot_port,
        "event_type": event_type,
        "raw_payload": raw_payload,
        "username": username,
        "password": password,
        "command": command,
        **(extra or {}),
    }

    try:
        client = get_client()
        resp = await client.post("/internal/events", json=payload)
        if resp.status_code != 200:
            log.warning(
                "backend returned %d for event from %s",
                resp.status_code, attacker_ip
            )
            return False
        return True
    except httpx.ConnectError:
        # backend not up yet or network blip — just log locally and move on
        log.warning("backend unreachable, event from %s dropped", attacker_ip)
        return False
    except Exception as e:
        log.error("unexpected error shipping event: %s", e)
        return False
