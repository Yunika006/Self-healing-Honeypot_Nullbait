"""
fake REST API honeypot — pretends to be an exposed internal API.
attracts automated scanners looking for unprotected API endpoints,
JWT token brute force, and GraphQL introspection attacks.
"""

import asyncio
import json
import logging
import os
import re

from utils.logger import log_event
from utils.geo_lookup import get_geo

log = logging.getLogger("nullbait.api")

# response helpers
def _json_resp(status: str, code: int, body: dict) -> bytes:
    body_str = json.dumps(body)
    return (
        f"HTTP/1.1 {code} {status}\r\n"
        f"Content-Type: application/json\r\n"
        f"X-Powered-By: Express\r\n"
        f"Content-Length: {len(body_str)}\r\n"
        f"\r\n"
        f"{body_str}"
    ).encode()


# fake API responses — realistic enough to keep scanners probing
ROUTES: dict[tuple[str, str], bytes] = {
    ("GET",  "/api/v1/health"):   _json_resp("OK", 200, {"status": "ok", "uptime": 3847392}),
    ("GET",  "/api/v1/users"):    _json_resp("Unauthorized", 401, {"error": "Unauthorized", "message": "Bearer token required"}),
    ("POST", "/api/v1/login"):    None,   # handled separately
    ("GET",  "/api/v1/config"):   _json_resp("Forbidden", 403, {"error": "Forbidden"}),
    ("GET",  "/api/v1/admin"):    _json_resp("Forbidden", 403, {"error": "Admin access required"}),
    ("POST", "/graphql"):         None,   # handled separately
    ("GET",  "/swagger.json"):    _json_resp("OK", 200, {
        "swagger": "2.0",
        "info": {"title": "Internal API", "version": "1.0"},
        "paths": {
            "/api/v1/users": {"get": {"description": "List users"}},
            "/api/v1/login": {"post": {"description": "Authenticate"}},
        }
    }),
}


async def handle_api_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    peer = writer.get_extra_info("peername")
    if not peer:
        writer.close()
        return

    attacker_ip, attacker_port = peer[0], peer[1]
    geo = await get_geo(attacker_ip)

    try:
        raw = await asyncio.wait_for(reader.read(16384), timeout=15.0)
        if not raw:
            return

        text = raw.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        if not lines:
            return

        parts = lines[0].split(" ")
        if len(parts) < 2:
            return

        method = parts[0].upper()
        path   = parts[1].split("?")[0]   # strip query string for routing

        # grab auth header if present — they might be trying tokens
        auth_header = ""
        content_type = ""
        for line in lines[1:]:
            ll = line.lower()
            if ll.startswith("authorization:"):
                auth_header = line[14:].strip()
            elif ll.startswith("content-type:"):
                content_type = line[13:].strip()

        # extract body
        body = ""
        if "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1].strip()

        log.info("api %s %s from %s", method, path, attacker_ip)

        await log_event(
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
            service="api",
            honeypot_port=int(os.getenv("API_HONEYPOT_PORT", 8888)),
            event_type="request",
            raw_payload=f"{method} {path}",
            extra={
                **geo,
                "method": method,
                "path": path,
                "auth_header": auth_header[:100] if auth_header else None,
                "body_preview": body[:200] if body else None,
            },
        )

        # login endpoint — log credentials
        if method == "POST" and path == "/api/v1/login":
            username, password = "", ""
            try:
                data = json.loads(body)
                username = data.get("username", data.get("email", ""))
                password = data.get("password", "")
            except json.JSONDecodeError:
                # might be form-encoded
                for part in body.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        if k in ("username", "email"):
                            username = v
                        elif k == "password":
                            password = v

            log.info("api login attempt from %s — user=%r pass=%r", attacker_ip, username, password)

            await log_event(
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                service="api",
                honeypot_port=int(os.getenv("API_HONEYPOT_PORT", 8888)),
                event_type="login_attempt",
                username=username,
                password=password,
                raw_payload=body[:500],
                extra=geo,
            )

            writer.write(_json_resp("Unauthorized", 401, {
                "error": "Invalid credentials",
                "code": "AUTH_FAILED"
            }))

        # graphql introspection attempt
        elif method == "POST" and path == "/graphql":
            await log_event(
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                service="api",
                honeypot_port=int(os.getenv("API_HONEYPOT_PORT", 8888)),
                event_type="payload",
                raw_payload=body[:500],
                extra={**geo, "attack_type": "graphql_introspection"},
            )
            # respond with a fake GraphQL error
            writer.write(_json_resp("OK", 200, {
                "errors": [{"message": "Not authorized to run introspection queries"}]
            }))

        elif (method, path) in ROUTES and ROUTES[(method, path)] is not None:
            writer.write(ROUTES[(method, path)])

        else:
            writer.write(_json_resp("Not Found", 404, {"error": "Not found"}))

        await writer.drain()

    except asyncio.TimeoutError:
        pass
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log.error("api handler error for %s: %s", attacker_ip, e)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_api_honeypot(port: int):
    server = await asyncio.start_server(
        handle_api_connection,
        host="0.0.0.0",
        port=port,
    )
    log.info("fake API honeypot listening on 0.0.0.0:%d", port)
    async with server:
        await server.serve_forever()
