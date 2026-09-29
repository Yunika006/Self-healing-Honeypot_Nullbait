"""
combines individual rule scores into one final threat score (0-100)
and a human readable threat level.
"""


def combine_scores(rule_results: list[dict]) -> dict:
    """
    rule_results: list of {"detected": bool, "score": int, "reason": str|None}
    from each rule module.

    we sum scores (capped at 100) rather than averaging, because
    multiple confirmed attack types from the same ip should compound —
    someone doing brute force AND sql injection is worse than either alone.
    """
    total_score = sum(r["score"] for r in rule_results)
    total_score = min(100, total_score)

    reasons = [r["reason"] for r in rule_results if r["detected"]]

    if total_score >= 75:
        level = "critical"
    elif total_score >= 50:
        level = "high"
    elif total_score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "score": total_score,
        "level": level,
        "reasons": reasons,
    }
