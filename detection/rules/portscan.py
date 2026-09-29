"""
port scan / service-hopping detection — flags an ip that touches
multiple different honeypot services in a short window. real
attackers/scanners often probe everything open on a host quickly.
"""


def check(events: list[dict]) -> dict:
    services_touched = {e["service"] for e in events}

    if len(services_touched) >= 3:
        score = min(35, 15 + len(services_touched) * 5)
        return {
            "detected": True,
            "score": score,
            "reason": f"touched {len(services_touched)} different services rapidly: {', '.join(sorted(services_touched))}",
        }

    return {"detected": False, "score": 0, "reason": None}
