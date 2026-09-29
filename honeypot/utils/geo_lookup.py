import asyncio
import logging
from functools import lru_cache

import httpx

log = logging.getLogger("nullbait.geo")

_geo_cache = {}


async def get_geo(ip: str) -> dict:
    if ip.startswith(("10.", "172.", "192.168.", "127.", "::1")):
        return {"country": "Private", "city": "LAN", "isp": "internal"}

    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "country,city,isp,status"}
            )
            data = resp.json()

            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                }
            else:
                result = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    except Exception:
        result = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    _geo_cache[ip] = result
    return result
