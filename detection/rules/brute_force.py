"""
brute force detection — counts login_attempt events per ip
within a rolling time window. flags anyone hammering past
the threshold.
"""

import os

THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", 5))
WINDOW_SECONDS = int(os.getenv("BRUTE_FORCE_WINDOW", 30))


def check(events: list[dict]) -> dict:
    """
    events: list of attack_events rows (as dicts) for ONE attacker ip,
    already filtered to the recent time window by the caller.

    returns: {"detected": bool, "score": int, "reason": str or None}
    """
    login_attempts = [e for e in events if e["event_type"] == "login_attempt"]
    count = len(login_attempts)

    if count >= THRESHOLD:
        # scale score with how far over threshold they are, capped at 40 points
        # contribution (brute force alone shouldn't maxout the score — that's
        # reserved for combos of multiple attack types)
        over = count - THRESHOLD
        score = min(40, 20 + over * 2)
        return {
            "detected": True,
            "score": score,
            "reason": f"{count} login attempts in {WINDOW_SECONDS}s (threshold: {THRESHOLD})",
        }

    return {"detected": False, "score": 0, "reason": None}
